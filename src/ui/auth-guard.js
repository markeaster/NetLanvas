/**
 * auth-guard.js
 *
 * Shared by every protected UI page. Wraps window.fetch so that any
 * response with status 401 (no valid session, enforced by the
 * @app.middleware("http") gate in src/api/server.py, scoped to /api/*)
 * redirects to the login page.
 *
 * Redirects the TOP-LEVEL window, not just the current frame, because
 * dashboard.html/links.html/etc. are loaded inside index.html's
 * <iframe id="content_frame">. Redirecting only the iframe would leave
 * a login form trapped inside the old, now-meaningless sidebar shell.
 *
 * The UI is served under the /dashboard static mount (see server.py's
 * app.mount("/dashboard", ...)), not domain root -- the redirect target
 * must match that.
 *
 * Also reframes a directly-loaded page (typed URL, bookmark, shared
 * link) back under index.html's sidebar shell -- every page below
 * assumes it's embedded in content_frame (nav highlighting, the
 * register-callback popup's window.opener.loadSettings() call, etc.),
 * so loading one standalone leaves the user on a bare page with no
 * sidebar/nav at all. index.html itself is excluded (it's meant to be
 * top-level); login.html doesn't include this script at all, since an
 * unauthenticated visitor has no shell to be re-embedded into.
 */
(function () {
    if (window.top === window && !window.location.pathname.endsWith('/index.html')) {
        const here = window.location.pathname.split('/').pop() + window.location.search;
        window.location.href = '/dashboard/index.html?page=' + encodeURIComponent(here);
        return;
    }

    const originalFetch = window.fetch.bind(window);

    window.fetch = async function (...args) {
        const response = await originalFetch(...args);
        if (response.status === 401) {
            // Found live 2026-09-17: content_frame's default page
            // (links.html, set as a static src="" so the common already-
            // set-up case doesn't pay for a redundant reload) starts
            // loading the instant the iframe tag is parsed -- before
            // index.html's own async /api/setup/status check has any
            // chance to redirect it to the setup modal instead. On a
            // genuinely fresh install (no account created yet), this
            // page's own authenticated fetch can 401 first and win that
            // race, bouncing the ENTIRE top-level window straight to
            // login.html for an account that doesn't exist -- no setup
            // modal ever shown, indistinguishable from a broken install.
            // Using originalFetch here, not the wrapped window.fetch, so
            // this check can never itself trigger this same handler.
            try {
                const setupRes = await originalFetch('/api/setup/status');
                const setupData = await setupRes.json();
                if (!setupData.setup_complete) {
                    (window.top || window).location.href = '/dashboard/index.html';
                    return new Promise(() => {});
                }
            } catch (e) {
                // /api/setup/status itself unreachable -- fall through to
                // the normal login redirect below rather than getting
                // stuck with no redirect at all.
            }
            (window.top || window).location.href = '/dashboard/login.html';
            // Prevent calling code from trying to .json()/parse this
            // response after we've already navigated away.
            return new Promise(() => {});
        }
        return response;
    };
})();
