// Shared "Report a Bug" banner + capture/submit flow. Self-contained:
// injects its own banner markup, modal markup, and styles at load
// time rather than requiring each page to carry duplicate HTML, the
// same pattern device-tooltip.js already established for shared UI
// pieces.
//
// LOCK-1 (2026-09-16): loaded from index.html's own <head> now, not
// from each individual content page -- real user report: this modal
// used to live inside content_frame's iframe document (one of the 12
// pages it loads), and content INSIDE an iframe can never visually or
// interactively out-rank an element in the PARENT document via
// z-index, no matter how high that z-index is set -- the whole iframe
// is capped at whatever stacking position it holds in the parent's
// own context. With index.html's own tick-lock-overlay/polling-paused-
// modal sitting at z-[9999] in the parent, this modal was rendering
// (and receiving clicks, when it received any at all) BEHIND them,
// genuinely un-fixable from inside the iframe. Loading this once in
// index.html itself puts it in the same document as those, where a
// real z-index comparison actually applies -- see the bumped value
// below. Nothing about the capture itself needed to change to make
// this safe: captureScreenshot() already grabs the whole visible tab
// via getDisplayMedia(), not anything scoped to "this document", so
// which document happens to own the script never mattered to what
// gets captured.
//
// Flow is deliberately screenshot-first: the capture happens the
// instant the button is clicked, before any modal/prompt appears, so
// nothing gets in the way of capturing the actual moment the bug was
// seen. Everything else (freetext, the telemetry-enable gate if
// needed) happens in review, after the image already exists.
(function () {
    'use strict';

    // Loaded from <head> (alongside auth-guard.js), same as every other
    // authenticated page -- so this runs while the parser is still
    // partway through <head>, before <body> exists in the DOM at all.
    // Deferring to DOMContentLoaded when needed (already-parsed pages,
    // e.g. a dynamically-injected re-run, skip straight to init())
    // avoids a TypeError on `document.body` that would otherwise abort
    // this whole script on every single load, silently -- confirmed
    // live 2026-09-10: exactly what was happening, on every page, the
    // banner never had a chance to inject at all.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    function init() {
    const BANNER_ID = 'bug-report-banner';
    if (document.getElementById(BANNER_ID)) return; // defensive: never double-inject

    const style = document.createElement('style');
    style.textContent = `
        #${BANNER_ID} {
            display: flex; align-items: center; justify-content: center; gap: 10px;
            background: #164e63; color: #a5f3fc; font-size: 12.5px;
            padding: 6px 16px; border-bottom: 1px solid #0e7490;
            /* sticky (not fixed): reserves its own space in normal flow
               where it's inserted (top of <body>), so no compensating
               padding is needed on the rest of the page, then pins to
               the viewport top once scrolled past -- confirmed live
               2026-09-10 the un-positioned version scrolled away with
               the page on every content-heavy page. z-index sits just
               below the review modal's overlay so the modal still
               displays above it when open -- see that rule's own
               comment for why both had to move above index.html's
               tick-lock-overlay/polling-paused-modal (z-[9999]) too,
               now that this all lives in that same document. */
            position: sticky; top: 0; z-index: 10000;
        }
        #${BANNER_ID} button {
            background: #06b6d4; color: #083344; border: none; border-radius: 5px;
            padding: 4px 12px; font-size: 12px; font-weight: 600; cursor: pointer;
        }
        #${BANNER_ID} button:hover { background: #22d3ee; }
        #bug-report-overlay {
            /* LOCK-1: 10001, deliberately above index.html's own
               locking overlays (tick-lock-overlay/polling-paused-modal,
               both z-[9999]) -- this needs to stay reachable and fully
               visible even while the rest of the UI is locked, not
               just clickable-but-dimmed-underneath. */
            position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 10001;
            display: flex; align-items: center; justify-content: center; padding: 24px;
        }
        #bug-report-overlay[hidden] { display: none; }
        #bug-report-modal {
            background: #111827; border: 1px solid #374151; border-radius: 10px;
            width: 100%; max-width: 560px; max-height: 88vh; overflow-y: auto;
            padding: 20px 22px; color: #e5e7eb; font-size: 13.5px;
        }
        #bug-report-modal h2 { margin: 0 0 12px; font-size: 16px; color: #f3f4f6; }
        #bug-report-modal img { width: 100%; border-radius: 6px; border: 1px solid #374151; margin-bottom: 14px; display: block; }
        #bug-report-modal textarea {
            width: 100%; min-height: 90px; background: #1f2937; color: #e5e7eb;
            border: 1px solid #374151; border-radius: 6px; padding: 8px 10px;
            font-size: 13px; resize: vertical; box-sizing: border-box;
        }
        #bug-report-telemetry-gate {
            background: #422006; border: 1px solid #b45309; border-radius: 6px;
            padding: 10px 12px; margin-bottom: 14px; font-size: 12.5px; color: #fde68a;
        }
        #bug-report-telemetry-gate button {
            margin-top: 8px; background: #f59e0b; color: #422006; border: none;
            border-radius: 5px; padding: 5px 12px; font-weight: 600; cursor: pointer; font-size: 12.5px;
        }
        #bug-report-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px; }
        #bug-report-actions button {
            border-radius: 6px; padding: 7px 16px; font-size: 13px; font-weight: 600; cursor: pointer; border: none;
        }
        #bug-report-cancel { background: transparent; color: #9ca3af; }
        #bug-report-cancel:hover { color: #e5e7eb; }
        #bug-report-submit { background: #06b6d4; color: #083344; }
        #bug-report-submit:hover:not(:disabled) { background: #22d3ee; }
        #bug-report-submit:disabled { background: #374151; color: #6b7280; cursor: not-allowed; }
        #bug-report-status { margin-top: 10px; font-size: 12.5px; }
        #bug-report-status.err { color: #fca5a5; }
        #bug-report-status.ok { color: #86efac; }
        /* TELEM-5 (2026-09-16): every real reason the structured send
           can fail -- telemetry off, the submission itself failing
           (any server or network reason), or no screenshot at all
           (permission denied/unsupported browser, which used to just
           quietly not open the modal) -- needs the same way out. See
           refreshFallbackUI() for exactly when this shows. */
        #bug-report-email-fallback {
            margin-top: 12px; padding-top: 12px; border-top: 1px solid #374151;
            font-size: 12.5px; color: #9ca3af; line-height: 1.6;
        }
        #bug-report-email-fallback[hidden] { display: none; }
        #bug-report-email-fallback button {
            background: transparent; color: #67e8f9; border: 1px solid #164e63;
            border-radius: 5px; padding: 3px 10px; font-size: 12px; font-weight: 600;
            cursor: pointer; margin: 4px 4px 0 0;
        }
        #bug-report-email-fallback button:hover { background: #164e63; }
    `;
    document.head.appendChild(style);

    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    // Register button starts hidden -- shown only once index.html's own
    // unified bootstrap (bootstrapApp(), 2026-09-17) tells us the
    // appliance isn't already registered, via window.NetLanvasSetRegistered
    // below. Deliberately NOT this script's own independent fetch of
    // /api/settings: bootstrapApp() already fetches that data once, as
    // part of deciding the whole page's state -- a second, uncoordinated
    // fetch of the same data from here was exactly the kind of
    // duplicated, racing check that caused SETUP-1 and the load-time
    // flicker. Placed in this always-visible, never-locked banner
    // because Settings' own Register card is easy to miss entirely
    // (real user report, 2026-09-17) and this is the one element
    // guaranteed visible on every page regardless of scan-lock state.
    banner.innerHTML = 'Found a problem? <button id="bug-report-btn" type="button">Report a Bug</button>' +
        '<button id="bug-report-register-btn" type="button" hidden>Register</button>';
    document.body.insertBefore(banner, document.body.firstChild);

    // Called by bootstrapApp() once it knows the real registration
    // status -- single source of truth, pushed down, not independently
    // re-derived here.
    window.NetLanvasSetRegistered = function (isRegistered) {
        const btn = document.getElementById('bug-report-register-btn');
        if (btn) btn.hidden = !!isRegistered;
    };

    document.getElementById('bug-report-register-btn').addEventListener('click', async () => {
        // Tab must open synchronously, in direct response to the click,
        // before any await -- otherwise most browsers silently block it
        // once the transient user-activation from the click has lapsed.
        // window.open() returns null rather than throwing when blocked,
        // so this can't be caught after the fact -- it has to be avoided
        // by construction. Found live 2026-09-17.
        const newTab = window.open('', '_blank');
        try {
            const res = await fetch('/api/register/initiate', { method: 'POST' });
            if (!res.ok) {
                if (newTab) newTab.close();
                return;
            }
            const data = await res.json();
            if (newTab) {
                newTab.location = data.redirect_url;
            } else {
                // Even the synchronous open above was blocked (rare, but
                // possible under strict popup settings) -- fall back to
                // navigating this tab's own top window rather than
                // leaving the click with no effect at all.
                window.top.location = data.redirect_url;
            }
        } catch (e) {
            if (newTab) newTab.close();
        }
    });

    const overlay = document.createElement('div');
    overlay.id = 'bug-report-overlay';
    overlay.hidden = true;
    overlay.innerHTML = `
        <div id="bug-report-modal">
            <h2>Report a Bug</h2>
            <img id="bug-report-preview" alt="Captured screenshot" hidden>
            <div id="bug-report-telemetry-gate" hidden>
                Bug reports are sent through the same channel as Community Telemetry, which is currently off.
                Enabling it is required to submit this report.
                <br><button id="bug-report-enable-telemetry" type="button">Enable Community Telemetry</button>
            </div>
            <textarea id="bug-report-message" placeholder="What went wrong? The more detail, the better."></textarea>
            <div id="bug-report-actions">
                <button id="bug-report-cancel" type="button">Cancel</button>
                <button id="bug-report-submit" type="button">Send Report</button>
            </div>
            <div id="bug-report-status"></div>
            <div id="bug-report-email-fallback" hidden>
                Can't send this way right now?
                <button id="bug-report-download-screenshot" type="button" hidden>Download Screenshot</button>
                <button id="bug-report-email" type="button">Report via Email</button>
                <span id="bug-report-email-hint"></span>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    const previewImg = document.getElementById('bug-report-preview');
    const gate = document.getElementById('bug-report-telemetry-gate');
    const messageBox = document.getElementById('bug-report-message');
    const submitBtn = document.getElementById('bug-report-submit');
    const statusEl = document.getElementById('bug-report-status');
    const emailFallback = document.getElementById('bug-report-email-fallback');
    const downloadScreenshotBtn = document.getElementById('bug-report-download-screenshot');
    const emailHint = document.getElementById('bug-report-email-hint');
    let screenshotB64 = null;
    let screenshotDataUrl = null;

    // TELEM-5 (2026-09-16): real user ask -- "all/any of those problems
    // could prevent a bug report, so email as an option." The
    // structured path (telemetry handshake -> submit-bug-report.php)
    // depends on several things that can each independently be
    // unavailable: telemetry opted in, the handshake/submission itself
    // succeeding (already seen fail server-side for reasons that have
    // nothing to do with the user, e.g. TELEM-4's stale-log-sample
    // cross-validation rejection), and even the screenshot capture
    // itself (permission denied, or getDisplayMedia unsupported --
    // previously just silently did nothing, no modal, no path forward
    // at all). Three independent booleans, tracked here rather than
    // inferred from DOM state scattered across several elements, so
    // one function can decide the right UI for whatever combination is
    // actually true right now.
    let telemetryOn = true; // optimistic default until refreshTelemetryGate() resolves
    let hasScreenshot = false;
    let lastSubmitFailed = false;

    function refreshFallbackUI() {
        const canSubmitNormally = hasScreenshot && telemetryOn;
        submitBtn.disabled = !canSubmitNormally;
        // Only nag about telemetry specifically when a screenshot is
        // the ONLY thing missing -- if there's no screenshot either,
        // that message would wrongly imply telemetry is the one thing
        // standing in the way.
        gate.hidden = telemetryOn || !hasScreenshot;
        downloadScreenshotBtn.hidden = !hasScreenshot;
        emailHint.textContent = hasScreenshot
            ? '-- attach the downloaded screenshot yourself once your email app opens.'
            : '-- no screenshot was captured, so this report will be text-only unless you attach one yourself.';
        emailFallback.hidden = canSubmitNormally && !lastSubmitFailed;
    }

    function closeModal() {
        overlay.hidden = true;
        previewImg.src = '';
        previewImg.hidden = true;
        messageBox.value = '';
        statusEl.textContent = '';
        statusEl.className = '';
        screenshotB64 = null;
        screenshotDataUrl = null;
        hasScreenshot = false;
        lastSubmitFailed = false;
    }

    async function refreshTelemetryGate() {
        try {
            const res = await fetch('/api/telemetry/nag-status');
            const data = await res.json();
            telemetryOn = !!data.submit_telemetry;
        } catch (e) {
            // Can't confirm either way -- the real enforcement is
            // server-side in /api/telemetry/submit-bug-report regardless
            // of what this client-side check showed, but NOT knowing
            // means the email fallback should stay available rather
            // than assume the structured path will actually work.
            telemetryOn = false;
        }
        refreshFallbackUI();
    }

    async function captureScreenshot() {
        let stream;
        try {
            // preferCurrentTab (Chrome-specific extension to the Screen
            // Capture API spec) is what actually makes the calling tab
            // itself capturable/pre-selected -- without it, Chrome's
            // tab-picker omits the current tab from the list entirely,
            // confirmed live 2026-09-10 (self-capture isn't the picker's
            // default assumption). Unrecognized by other browsers, which
            // just ignore the extra constraint and fall back to the
            // normal picker -- same behavior as before this fix there.
            stream = await navigator.mediaDevices.getDisplayMedia({ video: true, preferCurrentTab: true });
        } catch (e) {
            // User dismissed the picker or denied permission -- not an
            // error worth surfacing, they just changed their mind.
            return null;
        }
        try {
            const track = stream.getVideoTracks()[0];
            const video = document.createElement('video');
            video.srcObject = stream;
            await video.play();
            // ImageCapture is the direct route where available; a
            // one-frame <video>/<canvas> grab covers every browser that
            // supports getDisplayMedia but not ImageCapture (notably
            // Firefox).
            let bitmap;
            if (window.ImageCapture) {
                try {
                    bitmap = await new window.ImageCapture(track).grabFrame();
                } catch (e) { /* fall through to the video/canvas path */ }
            }
            const canvas = document.createElement('canvas');
            canvas.width = bitmap ? bitmap.width : video.videoWidth;
            canvas.height = bitmap ? bitmap.height : video.videoHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(bitmap || video, 0, 0, canvas.width, canvas.height);
            return canvas.toDataURL('image/png');
        } finally {
            stream.getTracks().forEach(t => t.stop());
        }
    }

    document.getElementById('bug-report-btn').addEventListener('click', async () => {
        const dataUrl = await captureScreenshot();
        // TELEM-5: used to `return` here on a null dataUrl (denied
        // permission, dismissed picker, or a browser without
        // getDisplayMedia at all) -- the modal never opened, no path
        // forward existed at all, not even the email fallback. Now
        // opens either way; refreshFallbackUI() (via hasScreenshot)
        // decides what's actually offered.
        hasScreenshot = !!dataUrl;
        if (dataUrl) {
            screenshotB64 = dataUrl.split(',')[1];
            screenshotDataUrl = dataUrl;
            previewImg.src = dataUrl;
            previewImg.hidden = false;
        } else {
            screenshotB64 = null;
            screenshotDataUrl = null;
        }
        overlay.hidden = false;
        refreshFallbackUI();
        refreshTelemetryGate();
    });

    document.getElementById('bug-report-enable-telemetry').addEventListener('click', async (e) => {
        e.target.disabled = true;
        e.target.textContent = 'Enabling...';
        try {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: 'SUBMIT_TELEMETRY', value: 'true' })
            });
        } catch (e) { /* refreshTelemetryGate below will re-show the gate if this silently failed */ }
        e.target.disabled = false;
        e.target.textContent = 'Enable Community Telemetry';
        refreshTelemetryGate();
    });

    document.getElementById('bug-report-cancel').addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

    // TELEM-5: pure client-side, no fetch at all -- deliberately, since
    // this exists specifically for when the appliance's own API can't
    // be trusted to work. previewImg.src is already the full data URL
    // captureScreenshot() produced; a plain <a download> against it
    // needs no canvas/blob conversion.
    downloadScreenshotBtn.addEventListener('click', () => {
        if (!screenshotDataUrl) return;
        const a = document.createElement('a');
        a.href = screenshotDataUrl;
        a.download = 'netlanvas-bug-screenshot.png';
        document.body.appendChild(a);
        a.click();
        a.remove();
    });

    document.getElementById('bug-report-email').addEventListener('click', () => {
        const message = messageBox.value.trim() || '(no description provided)';
        const bodyLines = [message, ''];
        if (hasScreenshot) {
            bodyLines.push('(Please attach the screenshot you downloaded before sending this email.)');
        }
        bodyLines.push('', 'Reported: ' + new Date().toISOString());
        const subject = encodeURIComponent('NetLanvas Bug Report');
        const body = encodeURIComponent(bodyLines.join('\n'));
        window.location.href = `mailto:feedback@netlanvas.com?subject=${subject}&body=${body}`;
    });

    submitBtn.addEventListener('click', async () => {
        if (!screenshotB64) return;
        submitBtn.disabled = true;
        statusEl.textContent = 'Sending...';
        statusEl.className = '';
        try {
            const res = await fetch('/api/telemetry/submit-bug-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: messageBox.value, screenshot_b64: screenshotB64 })
            });
            const data = await res.json();
            if (data.success) {
                statusEl.textContent = 'Thanks -- your report was sent.';
                statusEl.className = 'ok';
                lastSubmitFailed = false;
                setTimeout(closeModal, 1800);
            } else {
                statusEl.textContent = (data.error || 'Submission failed.') + ' You can email it instead below.';
                statusEl.className = 'err';
                lastSubmitFailed = true;
                refreshFallbackUI();
            }
        } catch (e) {
            statusEl.textContent = 'Submission failed -- network error. You can email it instead below.';
            statusEl.className = 'err';
            lastSubmitFailed = true;
            refreshFallbackUI();
        }
    });
    } // end init()
})();
