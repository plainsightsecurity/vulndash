</main>
<footer class="site-footer">
    <p>&copy; <?= date('Y') ?> Plainsight Security</p>
</footer>
<script>
(function () {
    var btn = document.getElementById('themeToggle');
    if (!btn) {
        return;
    }
    btn.addEventListener('click', function () {
        var isLight = document.documentElement.getAttribute('data-theme') === 'light';
        var next = isLight ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        try {
            window.localStorage.setItem('vulndash-theme', next);
        } catch (e) {
            // No persistence available (private browsing, etc) - the choice
            // still applies for the rest of this page view, it just won't
            // be remembered on the next one.
        }
    });
})();

// Mobile nav toggle - the hamburger button in src/views/header.php shows/
// hides #siteNav as a dropdown below the header on narrow viewports (see
// the "Mobile nav" block in style.css for the max-width this kicks in at).
// On wider viewports the toggle button itself is hidden by CSS and #siteNav
// is always visible as the normal horizontal bar, so none of this fires.
(function () {
    var toggle = document.getElementById('navToggle');
    var nav = document.getElementById('siteNav');
    if (!toggle || !nav) {
        return;
    }

    function closeNav() {
        nav.removeAttribute('data-open');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', 'Open menu');
    }

    function openNav() {
        nav.setAttribute('data-open', 'true');
        toggle.setAttribute('aria-expanded', 'true');
        toggle.setAttribute('aria-label', 'Close menu');
    }

    toggle.addEventListener('click', function () {
        if (nav.hasAttribute('data-open')) {
            closeNav();
        } else {
            openNav();
        }
    });

    // Tapping any link inside the open menu should close it, rather than
    // leaving the dropdown open underneath the page that just navigated to
    // (harmless on a full page load, but jarring for the instant it's
    // visible, and would otherwise stay open if the destination is the
    // same page, e.g. clicking "Dashboard" while already on it).
    nav.addEventListener('click', function (e) {
        if (e.target && e.target.tagName === 'A') {
            closeNav();
        }
    });

    document.addEventListener('click', function (e) {
        if (nav.hasAttribute('data-open') && !nav.contains(e.target) && !toggle.contains(e.target)) {
            closeNav();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && nav.hasAttribute('data-open')) {
            closeNav();
            toggle.focus();
        }
    });

    // Rotating a tablet (or resizing a browser window) from a mobile-width
    // layout back up past the desktop breakpoint shouldn't leave the menu
    // stuck open with mobile-only styling applied at a width where it's
    // supposed to just be the normal horizontal nav bar.
    window.addEventListener('resize', function () {
        if (window.innerWidth > 860 && nav.hasAttribute('data-open')) {
            closeNav();
        }
    });
})();

// Account menu - the user chip in src/views/header.php is a disclosure button
// that shows/hides the Preferences/Password/Security/Log out panel. Same
// click-toggle behaviour at every width: on desktop the panel is CSS-floated
// below the chip, inside the mobile hamburger it's an indented sub-list, but
// the JS is width-agnostic - it just flips the panel's `hidden` attribute and
// the button's aria-expanded, exactly like the tag-combo below.
(function () {
    var toggle = document.getElementById('accountMenuToggle');
    var panel = document.getElementById('accountMenu');
    if (!toggle || !panel) {
        return;
    }

    function closeMenu() {
        panel.hidden = true;
        toggle.setAttribute('aria-expanded', 'false');
    }

    function openMenu() {
        panel.hidden = false;
        toggle.setAttribute('aria-expanded', 'true');
    }

    toggle.addEventListener('click', function () {
        if (panel.hidden) {
            openMenu();
        } else {
            closeMenu();
        }
    });

    // A click anywhere outside the chip+panel closes it. Guarded on the panel
    // being open so this is a no-op the rest of the time. Note the mobile nav's
    // own outside-click handler above won't fire for clicks on the chip button
    // (it's inside #siteNav), so the two don't interfere.
    document.addEventListener('click', function (e) {
        if (!panel.hidden && !panel.contains(e.target) && !toggle.contains(e.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && !panel.hidden) {
            closeMenu();
            toggle.focus();
        }
    });

    // Rotating/resizing from the mobile layout (where the panel may have been
    // left expanded as a static sub-list) back up past the desktop breakpoint
    // shouldn't leave the floating desktop panel stuck open.
    window.addEventListener('resize', function () {
        if (window.innerWidth > 860 && !panel.hidden) {
            closeMenu();
        }
    });
})();

// Tag-selection comboboxes (Manage Users: Agent Tags / Scans) - a labelled
// button that opens a searchable, checkbox-based panel. Every .tag-combo on
// the page is wired up generically here, scoped to its own subtree, so this
// works the same whether there's one on the page or several (Agent Tags +
// Scans, in both the "Edit tags" and "Add a new user" forms) without any
// element needing a unique ID.
(function () {
    var combos = document.querySelectorAll('.tag-combo');
    if (!combos.length) {
        return;
    }

    function updateSummary(combo) {
        var summary = combo.querySelector('.tag-combo-summary');
        if (!summary) {
            return;
        }
        var checked = combo.querySelectorAll('input[type="checkbox"]:checked');
        if (checked.length === 0) {
            summary.textContent = 'None selected';
        } else if (checked.length === 1) {
            var option = checked[0].closest('.tag-combo-option');
            var label = option ? option.querySelector('span') : null;
            summary.textContent = label ? label.textContent : '1 selected';
        } else {
            summary.textContent = checked.length + ' selected';
        }
    }

    function closeCombo(combo) {
        var panel = combo.querySelector('.tag-combo-panel');
        var toggle = combo.querySelector('.tag-combo-toggle');
        if (panel) {
            panel.hidden = true;
        }
        if (toggle) {
            toggle.setAttribute('aria-expanded', 'false');
        }
        combo.removeAttribute('data-open');
    }

    function openCombo(combo) {
        combos.forEach(function (other) {
            if (other !== combo) {
                closeCombo(other);
            }
        });
        var panel = combo.querySelector('.tag-combo-panel');
        var toggle = combo.querySelector('.tag-combo-toggle');
        if (panel) {
            panel.hidden = false;
        }
        if (toggle) {
            toggle.setAttribute('aria-expanded', 'true');
        }
        combo.setAttribute('data-open', 'true');
        var search = combo.querySelector('.tag-combo-search');
        if (search) {
            search.focus();
        }
    }

    combos.forEach(function (combo) {
        var toggle = combo.querySelector('.tag-combo-toggle');
        var panel = combo.querySelector('.tag-combo-panel');
        var search = combo.querySelector('.tag-combo-search');
        var selectAllBtn = combo.querySelector('.tag-combo-selectall');
        var clearBtn = combo.querySelector('.tag-combo-clear');
        var emptyMsg = combo.querySelector('.tag-combo-empty');
        var options = combo.querySelectorAll('.tag-combo-option');

        updateSummary(combo);

        if (toggle) {
            toggle.addEventListener('click', function () {
                if (panel && panel.hidden) {
                    openCombo(combo);
                } else {
                    closeCombo(combo);
                }
            });
        }

        if (search) {
            search.addEventListener('input', function () {
                var term = search.value.trim().toLowerCase();
                var anyVisible = false;
                options.forEach(function (option) {
                    var match = term === '' || option.textContent.trim().toLowerCase().indexOf(term) !== -1;
                    option.hidden = !match;
                    if (match) {
                        anyVisible = true;
                    }
                });
                if (emptyMsg) {
                    emptyMsg.hidden = anyVisible;
                }
            });
        }

        // "Select all" only affects whatever the filter currently shows -
        // filter down, then bulk-select just that subset. "Clear" resets
        // the whole group regardless of any active filter.
        if (selectAllBtn) {
            selectAllBtn.addEventListener('click', function () {
                options.forEach(function (option) {
                    if (!option.hidden) {
                        var input = option.querySelector('input[type="checkbox"]');
                        if (input) {
                            input.checked = true;
                        }
                    }
                });
                updateSummary(combo);
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', function () {
                options.forEach(function (option) {
                    var input = option.querySelector('input[type="checkbox"]');
                    if (input) {
                        input.checked = false;
                    }
                });
                updateSummary(combo);
            });
        }

        combo.addEventListener('change', function (e) {
            if (e.target && e.target.matches('input[type="checkbox"]')) {
                updateSummary(combo);
            }
        });
    });

    document.addEventListener('click', function (e) {
        combos.forEach(function (combo) {
            if (combo.hasAttribute('data-open') && !combo.contains(e.target)) {
                closeCombo(combo);
            }
        });
    });

    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') {
            return;
        }
        combos.forEach(function (combo) {
            if (combo.hasAttribute('data-open')) {
                closeCombo(combo);
                var toggle = combo.querySelector('.tag-combo-toggle');
                if (toggle) {
                    toggle.focus();
                }
            }
        });
    });
})();

// Debounced search inputs (Assets/Vulnerabilities filter bars): waits for
// a short pause in typing before submitting the filter form, rather than
// reloading the page on every keystroke. Deliberately does NOT fire while
// the current value ends in a trailing space - a trailing space almost
// always means another word is still coming (typing "web " on the way to
// "web server"), so firing right then would just search a word fragment
// and immediately re-search a moment later. If someone stops typing with
// a trailing space and never continues, the field simply never submits
// that partial value - the previous results stay on screen, which is
// harmless, and correct: they never indicated they were done.
//
// Pressing Enter still submits immediately regardless of a trailing space
// - that's the browser's native "submit this form" behaviour for a text
// input, entirely separate from this debounce, and is a deliberate,
// explicit signal from the person typing rather than a guess.
//
// Every submission here is a full page reload (this app is plain GET
// forms throughout, no fetch/AJAX) - which would otherwise silently drop
// focus back to nowhere every time the debounce fires, making it feel
// like the page yanks the cursor away mid-sentence. sessionStorage is
// used to carry a "please refocus the search box, cursor at the end"
// signal across that reload: set right before a submission that this
// input itself caused (the debounce firing, Enter, or the clear button),
// read back (and immediately cleared) the moment this script runs on the
// next page. A reload caused by something else instead - a sort header, a
// tag dropdown, a pagination link - never sets that flag, so it
// deliberately does NOT steal focus back to search in those cases; only
// a search-triggered reload restores it.
(function () {
    var inputs = document.querySelectorAll('.search-debounce-input');
    if (!inputs.length) {
        return;
    }

    var DEBOUNCE_MS = 400;
    var FOCUS_FLAG = 'vulndash-refocus-search';

    try {
        if (window.sessionStorage.getItem(FOCUS_FLAG) === '1') {
            window.sessionStorage.removeItem(FOCUS_FLAG);
            var toRefocus = inputs[0]; // at most one search box exists on any given page
            if (toRefocus) {
                toRefocus.focus();
                var end = toRefocus.value.length;
                toRefocus.setSelectionRange(end, end);
            }
        }
    } catch (e) {
        // sessionStorage unavailable (private browsing, etc) - focus just
        // won't be restored across the reload; searching still works, only
        // this convenience is lost.
    }

    function markForRefocus() {
        try {
            window.sessionStorage.setItem(FOCUS_FLAG, '1');
        } catch (e) {
            // no-op - see the try/catch above
        }
    }

    inputs.forEach(function (input) {
        var timer = null;
        var wrap = input.closest('.search-input-wrap');
        var clearBtn = wrap ? wrap.querySelector('.search-clear') : null;

        function syncClearButton() {
            if (clearBtn) {
                clearBtn.hidden = input.value === '';
            }
        }
        syncClearButton();

        input.addEventListener('input', function () {
            syncClearButton();
            if (timer) {
                clearTimeout(timer);
            }
            timer = setTimeout(function () {
                if (/\s$/.test(input.value)) {
                    return;
                }
                markForRefocus();
                input.form.submit();
            }, DEBOUNCE_MS);
        });

        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                markForRefocus();
            }
        });

        if (clearBtn) {
            clearBtn.addEventListener('click', function () {
                input.value = '';
                syncClearButton();
                markForRefocus();
                input.form.submit();
            });
        }
    });
})();

// Vulnerability posture line chart hover tooltip - the one dashboard chart
// that's deliberately never clickable (everything else on the dashboard
// filters vulnerabilities.php when clicked; this one only ever shows the
// figure for whichever day the pointer is nearest to).
(function () {
    var svg = document.querySelector('.line-chart');
    if (!svg) {
        return;
    }
    var wrap = svg.closest('.line-chart-wrap');
    var tooltip = wrap ? wrap.querySelector('.line-chart-tooltip') : null;
    var dot = svg.querySelector('.line-hover-dot');
    if (!wrap || !tooltip || !dot) {
        return;
    }

    var points;
    try {
        points = JSON.parse(svg.getAttribute('data-points') || '[]');
    } catch (e) {
        points = [];
    }
    if (!points.length) {
        return;
    }

    var viewBox = svg.viewBox.baseVal;

    function nearestPoint(svgX) {
        var closest = points[0];
        var closestDist = Math.abs(points[0].x - svgX);
        for (var i = 1; i < points.length; i++) {
            var dist = Math.abs(points[i].x - svgX);
            if (dist < closestDist) {
                closest = points[i];
                closestDist = dist;
            }
        }
        return closest;
    }

    function showAt(clientX) {
        var svgRect = svg.getBoundingClientRect();
        var wrapRect = wrap.getBoundingClientRect();
        // Ratio-based mapping rather than getScreenCTM() matrix math - safe
        // here specifically because the CSS is width:100%; height:auto,
        // which always preserves the viewBox's aspect ratio exactly (no
        // letterboxing to account for), so a plain proportional mapping
        // from screen pixels to viewBox units is accurate.
        var xRatio = (clientX - svgRect.left) / svgRect.width;
        var svgX = viewBox.x + xRatio * viewBox.width;
        var point = nearestPoint(svgX);

        var pointXRatio = (point.x - viewBox.x) / viewBox.width;
        var pointYRatio = (point.y - viewBox.y) / viewBox.height;
        var left = (svgRect.left - wrapRect.left) + pointXRatio * svgRect.width;
        var top = (svgRect.top - wrapRect.top) + pointYRatio * svgRect.height;

        dot.setAttribute('cx', String(point.x));
        dot.setAttribute('cy', String(point.y));
        dot.hidden = false;

        tooltip.textContent = '';
        var strong = document.createElement('strong');
        strong.textContent = String(point.value);
        tooltip.appendChild(strong);
        tooltip.appendChild(document.createTextNode(' open on ' + point.label));

        // Unhide before measuring - offsetWidth/Height read 0 while hidden.
        tooltip.hidden = false;

        // Keep the bubble fully inside the wrap. The transform centres it on
        // `left` (translateX(-50%)), so clamp that centre to [halfW, width-halfW]
        // (+4px inset). Without this the rightmost/current day's tooltip spilled
        // past the right edge of the chart.
        var halfW = tooltip.offsetWidth / 2;
        var wrapW = wrapRect.width;
        var clampedLeft = Math.max(halfW + 4, Math.min(left, wrapW - halfW - 4));

        // Flip the bubble below the point when there isn't room above it, so the
        // tooltips for the tallest values aren't cut off at the top of the chart.
        var placeBelow = (top - tooltip.offsetHeight - 10) < 0;
        tooltip.classList.toggle('below', placeBelow);

        tooltip.style.left = clampedLeft + 'px';
        tooltip.style.top = top + 'px';
    }

    function hide() {
        dot.hidden = true;
        tooltip.hidden = true;
    }

    svg.addEventListener('mousemove', function (e) {
        showAt(e.clientX);
    });
    svg.addEventListener('mouseleave', hide);

    // Touch support: tapping/dragging the chart shows the nearest point's
    // tooltip the same way hovering with a mouse does.
    svg.addEventListener('touchstart', function (e) {
        if (e.touches[0]) {
            showAt(e.touches[0].clientX);
        }
    }, { passive: true });
    svg.addEventListener('touchmove', function (e) {
        if (e.touches[0]) {
            showAt(e.touches[0].clientX);
        }
    }, { passive: true });
})();

// Dashboard chart full-screen view. Each chart panel header carries an
// "expand" control next to its hint text and a matching "close" control,
// both rendered by public/dashboard.php and both starting hidden. This
// script un-hides the expand controls on load, which is the point of
// rendering them hidden: with JavaScript off nobody is shown a button
// that can't do anything.
//
// "Full screen" here is a fixed, viewport-filling layer applied to the
// panel in place (.chart-fullscreen in style.css) - NOT the native
// Element.requestFullscreen(). Two reasons: iOS Safari still doesn't
// support the Fullscreen API on non-video elements and this has to work
// the same on the phone layout; and leaving the panel exactly where it is
// in the DOM means everything inside it - the severity bars' and donut
// slices' <a> links, the line chart's hover tooltip - carries on working
// untouched, with no re-binding and no duplicated nodes.
//
// That's also why nothing here handles the "click a section while
// expanded" case: those really are links, so clicking one navigates to
// the filtered vulnerability list and this whole layer disappears with
// the page it was drawn on. Modifier and middle clicks keep their native
// open-in-new-tab behaviour, correctly leaving the expanded chart up.
(function () {
    var expandButtons = document.querySelectorAll('button[data-chart-expand]');
    if (!expandButtons.length) {
        return;
    }

    var openPanel = null;
    var returnFocusTo = null;

    // The two controls are a swap, never both visible: the expand button
    // is the affordance in the page, the close button the affordance in
    // the expanded view.
    function setControls(panel, expanded) {
        var expandBtn = panel.querySelector('button[data-chart-expand]');
        var closeBtn = panel.querySelector('button[data-chart-close]');
        if (expandBtn) {
            expandBtn.hidden = expanded;
        }
        if (closeBtn) {
            closeBtn.hidden = !expanded;
        }
    }

    // restoreFocus is false when closing only to make way for another
    // panel opening - that path sets focus itself, and pulling it back to
    // the old panel's expand button first would just fight it.
    function closeFullscreen(restoreFocus) {
        if (!openPanel) {
            return;
        }
        openPanel.classList.remove('chart-fullscreen');
        setControls(openPanel, false);
        openPanel = null;
        document.body.classList.remove('chart-fullscreen-open');
        if (restoreFocus && returnFocusTo) {
            returnFocusTo.focus();
        }
        returnFocusTo = null;
    }

    function openFullscreen(panel, trigger) {
        // Only ever one expanded at a time. Can't currently happen (the
        // expanded panel covers the other panels' buttons), but it costs
        // one line to not depend on that staying true.
        closeFullscreen(false);

        panel.classList.add('chart-fullscreen');
        setControls(panel, true);
        document.body.classList.add('chart-fullscreen-open');
        openPanel = panel;
        returnFocusTo = trigger;

        // The expanded panel is its own scroll container (charts can
        // overflow it on very short windows), so make sure it starts at
        // the top rather than wherever a previous expansion left it.
        panel.scrollTop = 0;

        var closeBtn = panel.querySelector('button[data-chart-close]');
        if (closeBtn) {
            closeBtn.focus();
        }
    }

    expandButtons.forEach(function (btn) {
        btn.hidden = false;
        btn.addEventListener('click', function () {
            var panel = btn.closest('.chart-panel');
            if (panel) {
                openFullscreen(panel, btn);
            }
        });
    });

    document.querySelectorAll('button[data-chart-close]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            closeFullscreen(true);
        });
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && openPanel) {
            closeFullscreen(true);
        }
    });
})();

// Dashboard "Top 10 most detected vulnerabilities" rows: the QID and title
// are already real <a> links (so the click-through works with JS disabled),
// but the whole row is made clickable as a convenience - the panel hint
// says "Click a row to filter". A primary click anywhere in the row that
// isn't already on one of those links navigates to the same filtered
// vulnerability list. Deliberately does NOT intercept modifier/middle
// clicks (open-in-new-tab etc.) or clicks that land on the real links -
// those keep their native behaviour, which also covers keyboard users, who
// tab straight to the links rather than the row.
(function () {
    var rows = document.querySelectorAll('.top-vulns-table tbody tr[data-href]');
    if (!rows.length) {
        return;
    }
    rows.forEach(function (row) {
        row.addEventListener('click', function (e) {
            if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
                return;
            }
            if (e.target.closest('a')) {
                return;
            }
            var href = row.getAttribute('data-href');
            if (href) {
                window.location.href = href;
            }
        });
    });
})();

// Off-site links open in a new tab, so a reader following a vendor advisory
// or CVE link doesn't lose the page they were on. Remediation text already
// gets target="_blank" server-side (Helpers::sanitizeVendorHtml() and
// linkifyPlainText()); this catches every other link to another site, on
// every page. Links within the dashboard are left alone and open in the same
// tab. Done at click time rather than as a one-off pass over the page, so
// links added after load are covered too: setting target here is picked up
// by the browser's own navigation, which runs after this handler. Links
// inside the remediation editor are skipped - clicking there is for editing,
// not following.
(function () {
    document.addEventListener('click', function (e) {
        if (e.defaultPrevented) {
            return;
        }
        var link = e.target && e.target.closest ? e.target.closest('a[href]') : null;
        if (!link || link.target || link.closest('[contenteditable="true"], .ck')) {
            return;
        }
        if ((link.protocol !== 'http:' && link.protocol !== 'https:') || link.host === window.location.host) {
            return;
        }
        link.target = '_blank';
        if (!/\bnoopener\b/.test(link.rel)) {
            link.rel = (link.rel + ' noopener noreferrer').trim();
        }
    });
})();
</script>
</body>
</html>
