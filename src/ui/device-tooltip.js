/**
 * device-tooltip.js
 *
 * Shared device-hover tooltip, extracted from links.html (Graph UI) so
 * every page that shows a device on hover -- Graph UI, the Subnets grid,
 * and whatever comes next -- renders it identically and only needs
 * fixing in one place. Deliberately Cytoscape-agnostic: the caller owns
 * whatever hover mechanism it has (a Cytoscape node event, a plain DOM
 * mouseover on a grid cell, etc.) and just calls show()/move()/hide()
 * with viewport coordinates + a plain data object.
 *
 * Usage:
 *   DeviceTooltip.show(clientX, clientY, {
 *       hostname, type,                          // header
 *       ip, mac, vlan, vendor, os, ssid, virtual, // body rows (omit a
 *       source, last_seen, clients, weld,         // key entirely to
 *       sysdescr,                                 // skip that row)
 *       warningBanner,                            // optional HTML string
 *       footerText,                               // optional, e.g. "Click to Inspect"
 *   });
 *   DeviceTooltip.move(clientX, clientY);   // on mousemove while still hovering
 *   DeviceTooltip.hide();
 */
const DeviceTooltip = (function () {
    const FIELD_ORDER = [
        ['ip', 'IP'],
        ['mac', 'MAC'],
        ['vlan', 'VLAN'],
        ['vendor', 'VENDOR'],
        ['category', 'CATEGORY'],
        ['market_segment', 'SEGMENT'],
        ['os', 'OS'],
        ['ssid', 'SSID'],
        ['virtual', 'VIRTUAL'],
        ['source', 'SOURCE'],
        ['last_seen', 'LAST SEEN'],
        ['clients', 'CLIENTS'],
        ['weld', 'WELD'],
        ['http_header', 'WEB'],
    ];
    // A handful of rows carry emphasis distinct from the plain
    // gray-200 default -- kept as a lookup rather than inline
    // conditionals so adding a new emphasized field later is a
    // one-line change here, not a template edit.
    const VALUE_CLASS = {
        vendor: 'col-span-2 font-bold text-sm text-gray-200 truncate',
        category: 'col-span-2 text-purple-400 truncate',
        market_segment: 'col-span-2 text-purple-400 truncate',
        clients: 'col-span-2 text-green-400 font-bold',
        weld: 'col-span-2 text-amber-400',
        last_seen: 'col-span-2 text-gray-200 text-[10px]',
        source: 'col-span-2 text-gray-200 text-[9px] truncate',
        http_header: 'col-span-2 text-cyan-300 text-[9px] truncate',
    };
    const DEFAULT_VALUE_CLASS = 'col-span-2 text-gray-200';

    const escapeHTML = (str) => {
        if (str === null || str === undefined) return '';
        return String(str).replace(/[&<>'"]/g, match => {
            const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' };
            return escapeMap[match];
        });
    };

    let el = null;
    function ensureEl() {
        if (el) return el;
        el = document.createElement('div');
        el.id = 'device-tooltip';
        // fixed, not absolute -- clientX/clientY are viewport-relative,
        // and this component may be used on a page that scrolls (unlike
        // Graph UI's fixed, non-scrolling canvas), so it must track the
        // viewport regardless of document scroll position.
        el.className = 'hidden fixed z-50 bg-gray-800/95 backdrop-blur-sm border border-gray-600 rounded shadow-2xl p-4 font-mono pointer-events-none w-80';
        document.body.appendChild(el);
        return el;
    }

    function render(data) {
        const rows = FIELD_ORDER
            .filter(([key]) => data[key] !== undefined)
            .map(([key, label]) => `<span class="text-cyan-500 font-bold">${label}:</span><span class="${VALUE_CLASS[key] || DEFAULT_VALUE_CLASS}">${escapeHTML(data[key])}</span>`)
            .join('');

        const sysdescrBlock = data.sysdescr !== undefined ? `
            <div class="mt-2 pt-2 border-t border-gray-700">
                <span class="text-cyan-500 font-bold text-[10px]">SYSDESCR:</span>
                <div class="text-gray-300 text-[9px] mt-0.5 max-h-16 overflow-y-auto leading-tight">${escapeHTML(data.sysdescr)}</div>
            </div>` : '';

        const footerBlock = data.footerText ? `
            <div class="mt-2 pt-2 border-t border-gray-700 text-center bg-gray-800/50 rounded p-1">
                <span class="text-blue-400 font-bold text-[10px] uppercase tracking-widest animate-pulse">${escapeHTML(data.footerText)}</span>
            </div>` : '';

        return `
            ${data.warningBanner || ''}
            <div class="border-b border-gray-700 pb-2 mb-2">
                <div class="text-blue-400 font-bold text-sm truncate uppercase tracking-wider">${escapeHTML(data.hostname)}</div>
                <div class="text-cyan-400 text-xs uppercase tracking-widest mt-0.5">${escapeHTML(data.type)}</div>
            </div>
            <div class="grid grid-cols-3 gap-y-1.5 gap-x-2 text-[11px]">${rows}</div>
            ${sysdescrBlock}
            ${footerBlock}
        `;
    }

    function move(x, y) {
        const tip = ensureEl();
        const offset = 15;
        let px = x + offset, py = y + offset;
        const w = tip.offsetWidth, h = tip.offsetHeight;
        if (px + w > window.innerWidth) px = x - w - offset;
        if (py + h > window.innerHeight) py = y - h - offset;
        tip.style.left = px + 'px';
        tip.style.top = py + 'px';
    }

    function show(x, y, data) {
        const tip = ensureEl();
        tip.innerHTML = render(data);
        tip.classList.remove('hidden');
        move(x, y);
    }

    function hide() {
        if (el) el.classList.add('hidden');
    }

    return { show, move, hide };
})();
