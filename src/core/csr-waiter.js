/**
 * CSRWaiter — Makes JAKU's page analysis Supabase/CSR-aware.
 *
 * Problem: Vibe-coded apps (Lovable, Bolt, Cursor) are almost always:
 *   - React/Vue SPAs with client-side rendering (CSR)
 *   - Supabase auth + DB queries that resolve ~500ms–3s after page load
 *   - Empty DOM shell at networkidle → real content appears later
 *
 * This causes a class of false positives in JAKU:
 *   - Broken flows flagged because content selectors don't exist yet
 *   - Forms not found, smoke tests fail, console errors from loading state
 *   - XSS inputs injected into hidden/non-existent fields
 *
 * Solution: Detect the auth provider in use, then apply the correct wait
 * strategy before any test phase touches the page.
 *
 * Supported providers detected automatically:
 *  • Supabase  (sb-*-auth-token in localStorage, GoTrueClient in JS)
 *  • Clerk     (window.Clerk, __clerk_db_jwt in cookies)
 *  • Firebase  (window.firebase, firebaseapp.com fetch)
 *  • Auth0     (window.auth0, .auth0.com/.well-known)
 *  • NextAuth  (window.__NEXTAUTH, /api/auth/session)
 *  • Generic CSR (React / Vue / Angular detected, any)
 */

const LOADING_SELECTORS = [
    // Generic loading indicators
    '[aria-busy="true"]',
    '[data-loading="true"]',
    '[data-state="loading"]',
    '.loading', '.spinner', '.skeleton', '.shimmer',
    '[class*="loading"]', '[class*="spinner"]', '[class*="skeleton"]', '[class*="shimmer"]',
    // Specific framework loading components
    '[class*="Skeleton"]', '[class*="Loading"]', '[class*="Spinner"]',
    // Radix/shadcn patterns common in vibe-coded apps
    '[data-radix-popper-content-wrapper]',
].join(', ');

// Auth error messages that are unconditionally safe to suppress —
// these ONLY appear from known auth library internals, never from app code.
const ALWAYS_SUPPRESS = [
    /supabase.*auth.*session/i,
    /getSession/i,
    /AuthSessionMissingError/i,
    /AuthRetryableFetchError/i,
    /invalid.*refresh.*token/i,
    /signIn.*required/i,
    /not.*authenticated/i,
    /jwt.*expired/i,
    /ResizeObserver loop/i,         // Harmless Radix/browser layout warning
    /Warning:.*defaultProps/i,      // React dev-mode warning, not a runtime error
];

// Errors that are ONLY suppressed within the first N ms of navigation.
// After that window closes, they surface as real findings — a component
// accessing uninitialized state after load is done is a genuine bug.
const EARLY_NAVIGATION_ERRORS = [
    /Cannot read propert.*undefined/i,
    /Cannot read propert.*null/i,
    /Failed to fetch/i,
    /NetworkError/i,
];

// How long (ms) after navigation start to consider errors as loading-state noise
const EARLY_NAVIGATION_WINDOW_MS = 2500;

export class CSRWaiter {
    constructor(logger) {
        this.logger = logger;
        this._detectedProvider = null; // cached after first detection
        this._navigationStartTime = null; // set each time waitForContent is called
    }

    /**
     * The main entry point — call this after page.goto() in any JAKU module.
     * Detects the auth provider and waits for content to fully settle.
     *
     * @param {import('playwright').Page} page
     * @param {object} options
     * @param {number} options.timeout — max ms to wait (default: 15000)
     * @param {boolean} options.strict — throw if page never settles (default: false)
     * @returns {{ provider: string, waited: boolean, elapsedMs: number }}
     */
    async waitForContent(page, { timeout = 15000, strict = false } = {}) {
        const start = Date.now();
        this._navigationStartTime = start; // used by time-gated error filter

        // Step 1: Detect provider (cache after first call per scan).
        // Detection is two-pass: primary signals first, then structural fallbacks.
        const provider = this._detectedProvider ?? await this._detectProvider(page);
        this._detectedProvider = provider;

        // Always log the detected provider so misdetections are debuggable
        this.logger?.debug?.(`CSRWaiter: provider=${provider} url=${page.url()}`);

        try {
            await Promise.race([
                this._waitStrategy(page, provider),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('CSRWaiter timeout')), timeout)
                ),
            ]);
        } catch (err) {
            if (strict) throw err;
            this.logger?.debug?.(
                `CSRWaiter: wait timed out for ${provider} after ${Date.now() - start}ms — proceeding with partial content`
            );
        }

        const elapsed = Date.now() - start;
        return { provider, waited: provider !== 'none', elapsedMs: elapsed };
    }

    /**
     * Run the appropriate wait strategy for the detected provider.
     */
    async _waitStrategy(page, provider) {
        switch (provider) {
            case 'supabase':
                await this._waitForSupabase(page);
                break;
            case 'clerk':
                await this._waitForClerk(page);
                break;
            case 'firebase':
            case 'auth0':
            case 'nextauth':
                await this._waitForGenericAuth(page, provider);
                break;
            case 'csr':
                await this._waitForCSRSettled(page);
                break;
            default:
                break; // SSR page, no special waiting needed
        }

        // Always run the DOM stability check last
        await this._waitForDOMStability(page, 400);
        await this._waitForLoadingGone(page);
    }

    /**
     * Detect which auth provider (if any) the app uses.
     *
     * Two-pass detection:
     *  Pass 1 — Primary signals: globals, localStorage keys, cookies.
     *            Fast; works on return visits where state is already written.
     *  Pass 2 — Structural signals: script src URLs, DOM markers, meta tags.
     *            Catches first-visit / incognito where localStorage is empty
     *            but the SDK is still loaded on the page.
     *
     * Fallback chain (explicit):
     *   Supabase primary → Supabase structural → Clerk → Firebase → Auth0
     *   → NextAuth → Generic CSR → None (SSR)
     */
    async _detectProvider(page) {
        try {
            const result = await page.evaluate(() => {
                // ── Pass 1: Primary runtime signals ──────────────────────────

                // Supabase: GoTrueClient global OR resolved auth token in localStorage
                const lsKeys = Object.keys(localStorage);
                const hasSupabaseLs = lsKeys.some(k => /^sb-.*-auth-token/.test(k));
                const hasSupabaseGlobal = typeof window.supabase !== 'undefined' ||
                    typeof window._supabase !== 'undefined';
                if (hasSupabaseLs || hasSupabaseGlobal) return 'supabase';

                // Clerk
                if (typeof window.Clerk !== 'undefined') return 'clerk';
                if (/__clerk_db_jwt/.test(document.cookie)) return 'clerk';

                // Firebase
                if (typeof window.firebase !== 'undefined' ||
                    typeof window.__FIREBASE_DEFAULTS__ !== 'undefined') return 'firebase';

                // Auth0
                if (typeof window.auth0 !== 'undefined') return 'auth0';

                // NextAuth
                if (typeof window.__NEXTAUTH !== 'undefined') return 'nextauth';

                // ── Pass 2: Structural / script-tag signals ───────────────────
                // Covers first-visit / incognito where localStorage is empty but
                // the SDK bundle is still present on the page.

                const scripts = [...document.querySelectorAll('script[src]')]
                    .map(s => s.src);

                // Supabase JS bundle loaded but not yet initialised (incognito / first visit)
                const hasSupabaseScript = scripts.some(s =>
                    /supabase/.test(s) || /cdn\.supabase/.test(s)
                );
                // Also check <meta> tags Lovable/Bolt sometimes emit
                const hasSupabaseMeta = !!document.querySelector(
                    '[data-supabase-url], meta[name="supabase-url"]'
                );
                if (hasSupabaseScript || hasSupabaseMeta) return 'supabase';

                // Clerk script tag
                if (scripts.some(s => /clerk/.test(s))) return 'clerk';

                // Firebase script tag
                if (scripts.some(s => /firebase/.test(s))) return 'firebase';

                // Auth0 script tag
                if (scripts.some(s => /auth0/.test(s))) return 'auth0';

                // ── Pass 3: Generic CSR framework markers ─────────────────────
                const hasCSRMarker = (
                    typeof window.React !== 'undefined' ||
                    typeof window.Vue !== 'undefined' ||
                    typeof window.angular !== 'undefined' ||
                    !!document.getElementById('__NEXT_DATA__') ||
                    !!document.getElementById('__nuxt') ||
                    !!document.querySelector('[data-reactroot], [ng-version]')
                );
                if (hasCSRMarker) return 'csr';

                return 'none';
            });

            return result;
        } catch (err) {
            // Page context lost or evaluate threw — log and fall back to CSR
            // so we still apply some waiting rather than nothing
            this.logger?.warn?.(`CSRWaiter: provider detection failed (${err.message}), defaulting to csr`);
            return 'csr';
        }
    }

    /**
     * Supabase-specific: wait for GoTrueClient to resolve auth state.
     * Supabase v2 fires `supabase:auth:INITIAL_SESSION` custom event or
     * updates localStorage once the session is determined.
     */
    async _waitForSupabase(page) {
        await page.waitForFunction(() => {
            // Strategy 1: Supabase has written auth state to localStorage
            const lsKeys = Object.keys(localStorage);
            const authKey = lsKeys.find(k => /^sb-.*-auth-token/.test(k));

            if (authKey) {
                try {
                    const val = JSON.parse(localStorage.getItem(authKey));
                    // Not loading if it resolved to null (anon) or has a user object
                    return val === null || (val && (val.user || val.access_token));
                } catch { return true; } // parse error = key exists = init done
            }

            // Strategy 2: Check if any auth-gated loading spinner is still visible
            const spinners = document.querySelectorAll(
                '[aria-busy="true"], [data-loading], [class*="loading"], [class*="spinner"]'
            );
            return spinners.length === 0;
        }, { timeout: 8000, polling: 200 }).catch(() => {
            // Fallback: just wait a fixed time for Supabase init
            return page.waitForTimeout(2000);
        });
    }

    /**
     * Clerk-specific: wait for Clerk to finish loading and resolve user state.
     */
    async _waitForClerk(page) {
        await page.waitForFunction(() => {
            if (typeof window.Clerk === 'undefined') return true;
            // Clerk exposes `isReady` once auth state is resolved
            return window.Clerk.isReady || window.Clerk.loaded;
        }, { timeout: 8000 }).catch(() => page.waitForTimeout(2000));
    }

    /**
     * Generic auth wait: poll for no loading indicators + network quiet.
     */
    async _waitForGenericAuth(page, provider) {
        // Wait for any in-flight fetches to complete
        await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => null);
        await this._waitForLoadingGone(page);
    }

    /**
     * Generic CSR wait: DOM stability + loading indicator gone.
     */
    async _waitForCSRSettled(page) {
        await page.waitForLoadState('domcontentloaded', { timeout: 5000 }).catch(() => null);
        await this._waitForLoadingGone(page);
    }

    /**
     * Wait until all loading spinners/skeletons/busy elements have disappeared.
     */
    async _waitForLoadingGone(page, timeout = 8000) {
        await page.waitForFunction((selectors) => {
            const el = document.querySelector(selectors);
            return !el;
        }, LOADING_SELECTORS, { timeout, polling: 150 }).catch(() => null);
    }

    /**
     * Wait until the DOM stops changing size (content settled).
     * Polls innerHTML length every 100ms and waits for stabilityMs of no change.
     *
     * Hard cap: DOM_STABILITY_MAX_MS. If hit, logs a warning and proceeds
     * rather than hanging — covers live-data dashboards with continuous mutations.
     */
    async _waitForDOMStability(page, stabilityMs = 400) {
        // Hard cap prevents indefinite hanging on dashboards with background
        // polling / websocket-driven DOM updates (e.g. realtime Supabase listeners)
        const DOM_STABILITY_MAX_MS = 4000;
        const deadline = Date.now() + DOM_STABILITY_MAX_MS;
        let lastSize = -1;
        let stableFor = 0;
        let hitCap = false;

        while (Date.now() < deadline) {
            const size = await page.evaluate(
                () => document.body?.innerHTML?.length ?? 0
            ).catch(() => 0);

            if (size === lastSize) {
                stableFor += 100;
                if (stableFor >= stabilityMs) break; // DOM settled — done
            } else {
                stableFor = 0;
                lastSize = size;
            }

            await page.waitForTimeout(100);
        }

        if (stableFor < stabilityMs) {
            hitCap = true;
            // Log warning so operators know why the wait ended early;
            // this is expected on live-data dashboards and is not an error.
            this.logger?.warn?.(
                `CSRWaiter: DOM stability cap hit after ${DOM_STABILITY_MAX_MS}ms on ${page.url()} — ` +
                `DOM may still be mutating (live data dashboard?). Proceeding with current state.`
            );
        }

        return { hitCap };
    }

    /**
     * Filter console messages to remove known loading-state noise.
     *
     * Two tiers:
     *  1. ALWAYS_SUPPRESS  — unconditionally removed (auth library internals only)
     *  2. EARLY_NAVIGATION_ERRORS — only suppressed within EARLY_NAVIGATION_WINDOW_MS
     *     of the navigation start time. After that window closes, these surface as
     *     real findings. A component crashing after load is done is a genuine bug.
     *
     * @param {string} message — console message text
     * @param {number|null} navigationStartTime — Date.now() at navigation start
     * @returns {boolean} — true if this message is a real error worth reporting
     */
    static isRealError(message, navigationStartTime = null) {
        // Tier 1: unconditional suppression
        if (ALWAYS_SUPPRESS.some(p => p.test(message))) return false;

        // Tier 2: time-gated suppression
        if (EARLY_NAVIGATION_ERRORS.some(p => p.test(message))) {
            if (navigationStartTime === null) {
                // No timing context available — suppress conservatively
                return false;
            }
            const age = Date.now() - navigationStartTime;
            // Within the early window → loading-state noise, suppress
            // Outside the window → genuine bug, surface it
            return age > EARLY_NAVIGATION_WINDOW_MS;
        }

        return true;
    }

    /**
     * Install a filtered console listener on a page. Returns an array
     * that will be populated with real (non-loading-noise) errors.
     * Captures navigationStartTime at install time for time-gated filtering.
     *
     * @param {import('playwright').Page} page
     * @param {number} [navigationStartTime] — defaults to Date.now()
     * @returns {Array<{type, text, timestamp}>}
     */
    static installConsoleFilter(page, navigationStartTime = Date.now()) {
        const realErrors = [];

        page.on('console', (msg) => {
            const type = msg.type();
            const text = msg.text();

            // Only capture warnings and errors
            if (type !== 'error' && type !== 'warning') return;

            // Apply two-tier filter with timing context
            if (!CSRWaiter.isRealError(text, navigationStartTime)) return;

            realErrors.push({
                type,
                text,
                timestamp: Date.now(),
                url: page.url(),
            });
        });

        return realErrors;
    }
}

export default CSRWaiter;
