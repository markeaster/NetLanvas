// Light/dark theme mechanism (punch-list item, requested 2026-09-04).
// Loaded right after vendor/tailwindcss.js -- Tailwind's browser/JIT
// build reads window.tailwind.config synchronously as soon as it's
// set (the same "set config after the main script tag" pattern its
// own CDN build documents), and both this assignment and the
// data-theme attribute below happen while <head> is still parsing,
// before <body> ever paints.
//
// Persisted as a normal appliance setting (UI_THEME, via the existing
// /api/settings key/value endpoint already used by every other
// Settings toggle) rather than per-browser -- this is meant to be
// consistent across whatever device/browser opens this appliance, not
// a personal per-browser preference. localStorage is used ONLY as an
// instant-apply cache to avoid a flash-of-wrong-theme while the
// authoritative server value loads; the async fetch below always
// reconciles and corrects it if they've drifted (e.g. changed from a
// different browser).
(function () {
    'use strict';

    var STORAGE_KEY = 'netlanvas_ui_theme';
    var root = document.documentElement;

    function applyTheme(theme) {
        if (theme === 'light') {
            root.setAttribute('data-theme', 'light');
        } else {
            root.removeAttribute('data-theme'); // dark is the unattributed default (theme.css's bare :root)
        }
    }

    // Instant, synchronous -- avoids a flash of the wrong theme on
    // every load after the first for a given browser.
    var cached = null;
    try { cached = localStorage.getItem(STORAGE_KEY); } catch (e) { /* private-browsing/storage-blocked -- fall through to server value only */ }
    if (cached === 'light' || cached === 'dark') applyTheme(cached);

    // index.html (the outer shell, owns the sidebar) and every page it
    // iframes into #content_frame (dashboard.html, settings.html, etc.)
    // are separate documents, each running their own independent copy
    // of this script -- setTheme() below only ever touches the ONE
    // document it's called from. Confirmed live 2026-09-10: toggling
    // the selector in Settings correctly re-themed the iframed page
    // instantly but left the sidebar dark, since nothing told the
    // OUTER document anything had changed.
    //
    // The browser's native `storage` event is the fix, not custom
    // cross-frame messaging -- it fires automatically in every OTHER
    // same-origin window/frame/tab watching localStorage (deliberately
    // never in the same document that made the change, which is
    // exactly the "the other frame" case here) the moment
    // localStorage.setItem() runs anywhere else on this origin.
    window.addEventListener('storage', function (e) {
        if (e.key === STORAGE_KEY && (e.newValue === 'light' || e.newValue === 'dark')) {
            applyTheme(e.newValue);
        }
    });

    // Tailwind's gray (the app's entire structural chrome -- backgrounds,
    // cards, borders, primary text) and cyan 400/500 (UI-1's own
    // secondary-text/accent color, used as pervasively as gray at this
    // point) both get remapped to theme.css's CSS variables. Every other
    // color family (severity badges, device-type category colors, etc.)
    // is deliberately left alone -- those are semantic identity colors
    // (a router is amber whether the theme is light or dark), not part
    // of the light/dark surface itself.
    window.tailwind = window.tailwind || {};
    window.tailwind.config = {
        theme: {
            extend: {
                colors: {
                    gray: {
                        50: 'var(--color-gray-50)', 100: 'var(--color-gray-100)', 200: 'var(--color-gray-200)',
                        300: 'var(--color-gray-300)', 400: 'var(--color-gray-400)', 500: 'var(--color-gray-500)',
                        600: 'var(--color-gray-600)', 700: 'var(--color-gray-700)', 800: 'var(--color-gray-800)',
                        900: 'var(--color-gray-900)'
                    },
                    cyan: { 400: 'var(--color-cyan-400)', 500: 'var(--color-cyan-500)' }
                }
            }
        }
    };

    // Authoritative reconciliation -- corrects the cached guess above
    // if the real appliance-wide setting differs (changed elsewhere,
    // or this is a first-ever load on this browser with no cache yet).
    fetch('/api/settings').then(function (r) { return r.json(); }).then(function (data) {
        var serverTheme = null;
        (Array.isArray(data.settings) ? data.settings : []).forEach(function (s) {
            if (s.setting_key === 'UI_THEME') serverTheme = s.setting_value;
        });
        if (serverTheme === 'light' || serverTheme === 'dark') {
            if (serverTheme !== cached) {
                applyTheme(serverTheme);
                try { localStorage.setItem(STORAGE_KEY, serverTheme); } catch (e) { /* ignore */ }
            }
        }
    }).catch(function () { /* keep whatever the cached/default value already applied */ });

    // Exposed for settings.html's theme selector -- applies instantly
    // (no reload needed) and persists both the server setting and the
    // local cache.
    window.NetLanvasTheme = {
        setTheme: function (theme) {
            applyTheme(theme);
            try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) { /* ignore */ }
            return fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: 'UI_THEME', value: theme })
            });
        },
        getCurrentTheme: function () {
            return root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
        }
    };
})();
