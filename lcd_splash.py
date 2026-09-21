import time
import socket
import board
import digitalio
import os
import qrcode
from PIL import Image, ImageDraw, ImageFont
from adafruit_rgb_display import ili9341

# Pin Configuration
cs_pin = digitalio.DigitalInOut(board.D23)
dc_pin = digitalio.DigitalInOut(board.D24)
reset_pin = digitalio.DigitalInOut(board.D25)
spi = board.SPI()

# Initialize landscape
disp = ili9341.ILI9341(spi, rotation=90, cs=cs_pin, dc=dc_pin, rst=reset_pin, baudrate=8000000)

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        return ip if ip != '127.0.0.1' else None
    except: return None
    finally: s.close()

def get_cpu_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            temp = int(f.read()) / 1000.0
        return f"{temp:.1f}°C"
    except:
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
            except: pass
            
    # 2. Try checking for PWM cooling device state
    try:
        with open("/sys/class/thermal/cooling_device0/cur_state", "r") as f:
            pwm = f.read().strip()
            return f"State: {pwm}"
    except:
        return "N/A"

def get_font(font_name, size, condensed=False):
    path = f"/usr/share/fonts/truetype/dejavu/{'DejaVuSansCondensed-Bold.ttf' if condensed else 'DejaVuSans.ttf'}"
    try: return ImageFont.truetype(path, size)
    except: return ImageFont.load_default()

def draw_screen(ip):
    w, h = 320, 240
    bg = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(bg)

    # 1. Title
    title_text = "Intelligent Infrastructure Visualisation"
    font_title = get_font("DejaVuSansCondensed-Bold.ttf", 14, condensed=True)
    tw = font_title.getlength(title_text)
    draw.text(((w - tw) // 2, 8), title_text, fill=(255, 255, 255), font=font_title)

    # 2. Hardware Stats
    stats_text = f"CPU Temp: {get_cpu_temp()}   |   Fan: {get_fan_speed()}"
    font_stats = get_font("DejaVuSans-Bold.ttf", 10)
    sw = font_stats.getlength(stats_text)
    # Draw it slightly below the title, colored in a subtle slate/blue
    draw.text(((w - sw) // 2, 28), stats_text, fill=(148, 163, 184), font=font_stats)

    if ip:
        # 3. Logo and QR
        logo_path = "/opt/appdata/netlanvas/src/ui/Netlanvas-Splash.png"
        if os.path.exists(logo_path):
            try:
                logo = Image.open(logo_path).convert("RGBA")
                logo.thumbnail((130, 130))
                bg.paste(logo, (20, 65), logo)
            except Exception as e: 
                print(f"Failed to process logo: {e}")

        # 4. Shortened URL
        short_url = f"https://{ip}:8899"
        qr = qrcode.make(short_url)
        qr = qr.resize((130, 130))
        bg.paste(qr, (170, 65))
        
        # 5. URL Text
        font_url = get_font("DejaVuSans-Bold.ttf", 16)
        uw = font_url.getlength(short_url)
        draw.text(((w - uw) // 2, h - 25), short_url, fill=(59, 130, 246), font=font_url)
    else:
        # No IP State
        font_msg = get_font("DejaVuSans-Bold.ttf", 20)
        msg = "Waiting for IP Address..."
        mw = font_msg.getlength(msg)
        draw.text(((w - mw) // 2, (h // 2) - 10), msg, fill=(255, 255, 0), font=font_msg)

    disp.image(bg)

if __name__ == "__main__":
    # Removed the 'last_ip' lock so the screen actively redraws the hardware stats
    while True:
        current_ip = get_ip()
        draw_screen(current_ip)
        time.sleep(5)
