"""
lcd_splash.py

Drives the physical ILI9341 status LCD (SPI0.0, CS/DC/RESET on GPIO
D23/D24/D25) -- CPU temp, fan speed, and a QR code linking to the
appliance's HTTPS UI. Runs as netlanvas_lcd.service, root, forever.

LCD-1 (2026-09-23): originally a genuinely silent loop by design (no
logging at all, redraws every 5s) -- but that meant a real failure
mode was invisible for as long as the process itself stayed alive.
Confirmed live: the panel can silently desync from an otherwise
perfectly healthy process (valid SPI/GPIO handles held the whole time,
zero exceptions, zero kernel-level SPI/undervoltage errors) and just
show blank white, forever, with nothing in the software stack ever
noticing -- because the actual SPI write (disp.image()) had no error
handling, and the ILI9341's hardware RESET pin was only ever pulsed
once, at process start.

Rewritten with:
  - real logging (to stderr, which the systemd unit now correctly
    routes to the journal -- see the StandardOutput=inherit fix
    applied alongside this) instead of silent bare excepts
  - error handling around every actual hardware/IO call, not just
    the cosmetic ones
  - a consecutive-failure counter on the actual display write, which
    forces an immediate re-init instead of waiting up to 10 minutes
  - the existing periodic re-init (every 10 min) kept as a backstop

Deliberately NOT logging every successful 5s draw -- that would just
be a different kind of noise. What's logged: startup, state changes
(IP appearing/disappearing), every re-init attempt and its outcome,
every real failure, and a low-frequency heartbeat so "quiet" can be
read as "working" rather than "logging is broken too."
"""
import logging
import os
import socket
import sys
import time

import board
import digitalio
import qrcode
from PIL import Image, ImageDraw, ImageFont
from adafruit_rgb_display import ili9341

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("Netlanvas.LCD")

# Pin Configuration
cs_pin = digitalio.DigitalInOut(board.D23)
dc_pin = digitalio.DigitalInOut(board.D24)
reset_pin = digitalio.DigitalInOut(board.D25)
spi = board.SPI()


def init_display():
    """(Re-)initializes the panel. This is the only thing that pulses
    the hardware RESET pin, so calling it again is the actual fix for
    a panel that's desynced from an otherwise-healthy process, not
    just a formality."""
    return ili9341.ILI9341(spi, rotation=90, cs=cs_pin, dc=dc_pin, rst=reset_pin, baudrate=8000000)


disp = init_display()
logger.info("Display initialized.")


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        return ip if ip != "127.0.0.1" else None
    except OSError as e:
        logger.debug(f"get_ip: no route yet ({e})")
        return None
    finally:
        s.close()


def get_cpu_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            temp = int(f.read()) / 1000.0
        return f"{temp:.1f}°C"
    except (OSError, ValueError) as e:
        logger.debug(f"get_cpu_temp unavailable: {e}")
        return "N/A"


def get_fan_speed():
    # 1. Try checking for hardware tachometer (RPM)
    hwmon_dirs = ["/sys/class/hwmon/hwmon0", "/sys/class/hwmon/hwmon1", "/sys/class/hwmon/hwmon2"]
    for d in hwmon_dirs:
        fan_path = os.path.join(d, "fan1_input")
        if os.path.exists(fan_path):
            try:
                with open(fan_path, "r") as f:
                    return f"{f.read().strip()} RPM"
            except OSError as e:
                logger.debug(f"get_fan_speed: {fan_path} unreadable ({e})")

    # 2. Try checking for PWM cooling device state
    try:
        with open("/sys/class/thermal/cooling_device0/cur_state", "r") as f:
            pwm = f.read().strip()
            return f"State: {pwm}"
    except (OSError, ValueError) as e:
        logger.debug(f"get_fan_speed: cooling_device0 unavailable ({e})")
        return "N/A"


_font_warned = set()


def get_font(size, condensed=False):
    name = "DejaVuSansCondensed-Bold.ttf" if condensed else "DejaVuSans.ttf"
    path = f"/usr/share/fonts/truetype/dejavu/{name}"
    try:
        return ImageFont.truetype(path, size)
    except Exception as e:
        # Only warn once per font -- this fires every 5s otherwise if
        # the font package is ever missing, which is its own kind of
        # log-noise problem.
        if path not in _font_warned:
            logger.warning(f"Falling back to default font, {path} failed to load: {e}")
            _font_warned.add(path)
        return ImageFont.load_default()


def draw_screen(ip):
    w, h = 320, 240
    bg = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(bg)

    # 1. Title
    title_text = "Intelligent Infrastructure Visualisation"
    font_title = get_font(14, condensed=True)
    tw = font_title.getlength(title_text)
    draw.text(((w - tw) // 2, 8), title_text, fill=(255, 255, 255), font=font_title)

    # 2. Hardware Stats
    stats_text = f"CPU Temp: {get_cpu_temp()}   |   Fan: {get_fan_speed()}"
    font_stats = get_font(10)
    sw = font_stats.getlength(stats_text)
    draw.text(((w - sw) // 2, 28), stats_text, fill=(148, 163, 184), font=font_stats)

    if ip:
        # 3. Logo
        logo_path = "/opt/appdata/netlanvas/src/ui/Netlanvas-Splash.png"
        if os.path.exists(logo_path):
            try:
                logo = Image.open(logo_path).convert("RGBA")
                logo.thumbnail((130, 130))
                bg.paste(logo, (20, 65), logo)
            except Exception as e:
                logger.warning(f"Failed to process logo: {e}")

        # 4. QR code
        short_url = f"https://{ip}:8899"
        try:
            qr = qrcode.make(short_url)
            qr = qr.resize((130, 130))
            bg.paste(qr, (170, 65))
        except Exception as e:
            logger.warning(f"Failed to generate QR code for {short_url}: {e}")

        # 5. URL Text
        font_url = get_font(16)
        uw = font_url.getlength(short_url)
        draw.text(((w - uw) // 2, h - 25), short_url, fill=(59, 130, 246), font=font_url)
    else:
        # No IP State
        font_msg = get_font(20)
        msg = "Waiting for IP Address..."
        mw = font_msg.getlength(msg)
        draw.text(((w - mw) // 2, (h // 2) - 10), msg, fill=(255, 255, 0), font=font_msg)

    # The actual write to the panel -- this is the call that was
    # silently failing before LCD-1. A failure here is the caller's
    # signal to count toward a forced re-init, not something to
    # swallow at this level.
    disp.image(bg)


if __name__ == "__main__":
    REINIT_EVERY_TICKS = 120  # 120 * 5s = 10 minutes
    MAX_CONSECUTIVE_FAILURES = 3
    HEARTBEAT_EVERY_TICKS = 720  # 720 * 5s = 1 hour

    logger.info("LCD monitor loop starting.")
    tick = 0
    consecutive_failures = 0
    last_ip = "<unset>"

    while True:
        if tick and tick % REINIT_EVERY_TICKS == 0:
            logger.info("Periodic re-init (scheduled).")
            try:
                disp = init_display()
                consecutive_failures = 0
            except Exception as e:
                logger.error(f"Periodic re-init failed: {e}")

        current_ip = get_ip()
        if current_ip != last_ip:
            logger.info(f"IP changed: {last_ip} -> {current_ip}")
            last_ip = current_ip

        try:
            draw_screen(current_ip)
            consecutive_failures = 0
        except Exception as e:
            consecutive_failures += 1
            logger.error(f"draw_screen failed ({consecutive_failures}/{MAX_CONSECUTIVE_FAILURES} consecutive): {e}")
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                logger.warning("Too many consecutive draw failures, forcing an immediate re-init.")
                try:
                    disp = init_display()
                    consecutive_failures = 0
                    logger.info("Forced re-init succeeded.")
                except Exception as reinit_err:
                    logger.error(f"Forced re-init also failed: {reinit_err}")

        if tick and tick % HEARTBEAT_EVERY_TICKS == 0:
            logger.info(f"Heartbeat: alive, tick={tick}, ip={current_ip}.")

        time.sleep(5)
        tick += 1
