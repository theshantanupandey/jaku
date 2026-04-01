import { BrowserManager } from './browser-manager.js';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { Writable } from 'stream';

/**
 * AuthManager — Handles authenticated scanning.
 * 
 * Supports 3 login strategies:
 * 1. Form-based: Auto-detects login forms, fills credentials, submits
 * 2. API-based: POSTs JSON to login endpoint, extracts tokens
 * 3. Cookie injection: Uses pre-configured session cookies
 * 
 * Stores Playwright storageState (cookies + localStorage) per role.
 * All downstream agents inherit auth context automatically.
 */
export class AuthManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.authStates = new Map();  // role → { state, postLoginUrl, discoveredLinks }
        this.authTokens = new Map();  // role → { token, type }
        this._browser = null;
    }

    /**
     * Authenticate all configured credentials.
     * If no credentials are configured but a login form is detected,
     * interactively prompts the user in the terminal.
     * Returns a Map of role → storageState for Playwright contexts.
     */
    async authenticate() {
        let credentials = this.config.credentials || [];

        // If no credentials configured, check for login form and prompt interactively
        if (credentials.filter(c => c.username && c.password).length === 0) {
            const loginUrl = this.config.auth?.login_url || await this._discoverLoginPage();
            if (loginUrl) {
                const prompted = await this._promptForCredentials(loginUrl);
                if (!prompted) {
                    this.logger?.info?.('No credentials provided — scanning unauthenticated');
                    return this.authStates;
                }
                // _promptForCredentials already verified + stored the auth state
                // so we can return directly
                this.logger?.info?.(`Auth complete: ${this.authStates.size} role(s) authenticated`);
                return this.authStates;
            } else {
                this.logger?.info?.('No login form detected — scanning unauthenticated');
                return this.authStates;
            }
        }

        // CLI flags or config provided credentials — authenticate them
        const authConfig = this.config.auth || {};
        this._browser = await BrowserManager.launch({ headless: true });

        for (const cred of credentials) {
            if (!cred.username || !cred.password) {
                this.logger?.debug?.(`Skipping role "${cred.role}" — no username/password`);
                continue;
            }

            try {
                const strategy = authConfig.strategy || 'auto';
                this.logger?.info?.(`Authenticating as "${cred.role}" via ${strategy}...`);

                let state;
                switch (strategy) {
                    case 'form':
                        state = await this._loginViaForm(cred, authConfig);
                        break;
                    case 'api':
                        state = await this._loginViaAPI(cred, authConfig);
                        break;
                    case 'cookie':
                        state = await this._injectCookies(cred, authConfig);
                        break;
                    case 'auto':
                    default:
                        state = await this._autoLogin(cred, authConfig);
                        break;
                }

                if (state) {
                    this.authStates.set(cred.role, state);
                    const cookieCount = state.state?.cookies?.length || state.cookies?.length || 0;
                    this.logger?.info?.(`✔ Authenticated as "${cred.role}" — ${cookieCount} cookies stored`);
                } else {
                    this.logger?.warn?.(`✘ Authentication failed for "${cred.role}"`);
                }
            } catch (err) {
                this.logger?.error?.(`Auth error for "${cred.role}": ${err.message}`);
            }
        }

        await this._browser.close();
        this._browser = null;

        this.logger?.info?.(`Auth complete: ${this.authStates.size}/${credentials.filter(c => c.username).length} roles authenticated`);
        return this.authStates;
    }

    /**
     * Auto-detect login strategy: try form first, fall back to API.
     */
    async _autoLogin(cred, authConfig) {
        // Step 1: Find login page
        const loginUrl = authConfig.login_url || await this._discoverLoginPage();
        if (!loginUrl) {
            this.logger?.debug?.('No login page found — trying API login');
            return this._loginViaAPI(cred, authConfig);
        }

        // Step 2: Try form-based login
        const state = await this._loginViaForm(cred, { ...authConfig, login_url: loginUrl });
        if (state) return state;

        // Step 3: Fall back to API login
        return this._loginViaAPI(cred, authConfig);
    }

    /**
     * Form-based login: navigate to login page, fill form, submit.
     */
    async _loginViaForm(cred, authConfig) {
        const loginUrl = authConfig.login_url || `${this.config.target_url}/login`;
        const context = await this._browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });
        const page = await context.newPage();

        try {
            await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: 15000 });

            // Find the login form
            const usernameSelector = authConfig.username_selector || await this._findUsernameField(page);
            const passwordSelector = authConfig.password_selector || await this._findPasswordField(page);
            const submitSelector = authConfig.submit_selector || await this._findSubmitButton(page);

            if (!usernameSelector || !passwordSelector) {
                this.logger?.debug?.('Could not find login form fields');
                await page.close();
                await context.close();
                return null;
            }

            // Fill credentials
            await page.fill(usernameSelector, cred.username);
            await page.fill(passwordSelector, cred.password);

            // Submit and wait for navigation
            const [response] = await Promise.all([
                page.waitForNavigation({ waitUntil: 'networkidle', timeout: 10000 }).catch(() => null),
                submitSelector
                    ? page.click(submitSelector)
                    : page.keyboard.press('Enter'),
            ]);

            // Verify login succeeded
            const loggedIn = await this._verifyLogin(page, loginUrl);
            if (!loggedIn) {
                this.logger?.debug?.(`Form login failed for "${cred.role}" — still on login page`);
                await page.close();
                await context.close();
                return null;
            }

            // Capture post-login URL (e.g., /dashboard, /app, /home)
            const postLoginUrl = page.url();
            this.logger?.debug?.(`Post-login URL: ${postLoginUrl}`);

            // Discover links on the post-login page (authenticated pages to crawl)
            const discoveredLinks = await page.evaluate(() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                return anchors.map(a => a.href)
                    .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('mailto:'));
            }).catch(() => []);

            this.logger?.debug?.(`Post-login page has ${discoveredLinks.length} links`);

            // Extract storage state (cookies + localStorage)
            const state = await context.storageState();
            await page.close();
            await context.close();
            return { state, postLoginUrl, discoveredLinks };
        } catch (err) {
            this.logger?.debug?.(`Form login error: ${err.message}`);
            await page.close().catch(() => { });
            await context.close().catch(() => { });
            return null;
        }
    }

    /**
     * API-based login: POST credentials to login endpoint.
     */
    async _loginViaAPI(cred, authConfig) {
        const loginEndpoints = authConfig.api_login_url
            ? [authConfig.api_login_url]
            : [
                `${this.config.target_url}/api/auth/login`,
                `${this.config.target_url}/api/login`,
                `${this.config.target_url}/auth/login`,
                `${this.config.target_url}/api/v1/auth/login`,
                `${this.config.target_url}/api/sessions`,
            ];

        for (const endpoint of loginEndpoints) {
            try {
                const resp = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: cred.username,
                        username: cred.username,
                        password: cred.password,
                    }),
                    signal: AbortSignal.timeout(10000),
                });

                if (resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    const token = data.token || data.access_token || data.accessToken
                        || data.jwt || data.session_token || data.data?.token;

                    if (token) {
                        this.authTokens.set(cred.role, {
                            token,
                            type: data.token_type || 'Bearer',
                        });

                        // Create a browser context with the token as a cookie
                        const context = await this._browser.newContext({
                            ignoreHTTPSErrors: true,
                        });

                        // Set cookies from response
                        const setCookieHeaders = resp.headers.getSetCookie?.() || [];
                        if (setCookieHeaders.length > 0) {
                            const cookies = this._parseSetCookieHeaders(setCookieHeaders);
                            await context.addCookies(cookies);
                        }

                        // Also add token as localStorage
                        const page = await context.newPage();
                        await page.goto(this.config.target_url, { waitUntil: 'domcontentloaded', timeout: 10000 });
                        await page.evaluate((tkn) => {
                            localStorage.setItem('token', tkn);
                            localStorage.setItem('access_token', tkn);
                            localStorage.setItem('auth_token', tkn);
                        }, token);

                        const state = await context.storageState();
                        await page.close();
                        await context.close();

                        this.logger?.debug?.(`API login succeeded at ${endpoint}`);
                        return state;
                    }

                    // No token but 200 — might use cookies only
                    const setCookieHeaders = resp.headers.getSetCookie?.() || [];
                    if (setCookieHeaders.length > 0) {
                        const context = await this._browser.newContext({ ignoreHTTPSErrors: true });
                        const cookies = this._parseSetCookieHeaders(setCookieHeaders);
                        await context.addCookies(cookies);
                        const state = await context.storageState();
                        await context.close();
                        this.logger?.debug?.(`API login succeeded at ${endpoint} (cookie-based)`);
                        return state;
                    }
                }
            } catch {
                // Try next endpoint
            }
        }

        return null;
    }

    /**
     * Cookie injection: use pre-configured cookies from config.
     */
    async _injectCookies(cred, authConfig) {
        const cookies = cred.cookies || authConfig.cookies || [];
        if (cookies.length === 0) return null;

        const context = await this._browser.newContext({ ignoreHTTPSErrors: true });
        const targetUrl = new URL(this.config.target_url);

        const playwrightCookies = cookies.map(c => ({
            name: c.name,
            value: c.value,
            domain: c.domain || targetUrl.hostname,
            path: c.path || '/',
            httpOnly: c.httpOnly ?? true,
            secure: c.secure ?? targetUrl.protocol === 'https:',
            sameSite: c.sameSite || 'Lax',
        }));

        await context.addCookies(playwrightCookies);
        const state = await context.storageState();
        await context.close();
        return state;
    }

    // ═══ Helper Methods ═══

    /**
     * Discover login page by probing common login URLs.
     * Uses Playwright to render pages (SPAs render login forms via JS).
     */
    async _discoverLoginPage() {
        const paths = ['/login', '/signin', '/auth/login', '/auth/signin', '/sign-in',
            '/account/login', '/user/login', '/admin/login', '/api/auth/signin',
            '/sign_in', '/users/sign_in', '/session/new'];
        const baseUrl = this.config.target_url;

        // Launch a browser to render pages (SPA login forms are JS-rendered)
        let browser;
        try {
            browser = await BrowserManager.launch({ headless: true });
        } catch {
            // Fallback to fetch if browser can't launch
            return this._discoverLoginPageViaFetch();
        }

        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        try {
            for (const p of paths) {
                try {
                    const url = new URL(p, baseUrl).href;
                    const page = await context.newPage();

                    const response = await page.goto(url, {
                        waitUntil: 'networkidle',
                        timeout: 10000,
                    });

                    if (!response || response.status() >= 400) {
                        await page.close();
                        continue;
                    }

                    // Check the rendered DOM for password fields
                    const hasLoginForm = await page.evaluate(() => {
                        const passwordField = document.querySelector('input[type="password"]');
                        if (passwordField) return true;

                        // Check for login-related text in the page
                        const bodyText = document.body?.textContent?.toLowerCase() || '';
                        const hasLoginText = /sign\s*in|log\s*in|authenticate|enter.*password/i.test(bodyText);
                        const hasEmailField = !!document.querySelector('input[type="email"], input[name="email"], input[name="username"]');
                        return hasLoginText && hasEmailField;
                    });

                    await page.close();

                    if (hasLoginForm) {
                        this.logger?.info?.(`Discovered login page: ${url}`);
                        await context.close();
                        await browser.close();
                        return url;
                    }
                } catch {
                    // Skip this path
                }
            }

            // Also check the homepage itself — some SPAs have login right on the main page
            try {
                const page = await context.newPage();
                await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 10000 });

                // Check if login form is directly on the homepage
                const hasPasswordOnHome = await page.$('input[type="password"]');
                if (hasPasswordOnHome) {
                    this.logger?.info?.(`Discovered login form on homepage: ${baseUrl}`);
                    await page.close();
                    await context.close();
                    await browser.close();
                    return baseUrl;
                }

                // Check for login links that might lead to a login form
                const loginLink = await page.$('a:has-text("Log in"), a:has-text("Sign in"), a:has-text("Login"), a:has-text("Sign In")');
                if (loginLink) {
                    await loginLink.click();
                    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => { });
                    const loginUrl = page.url();
                    const hasPasswordNow = await page.$('input[type="password"]');
                    await page.close();
                    if (hasPasswordNow) {
                        this.logger?.info?.(`Discovered login page via navigation: ${loginUrl}`);
                        await context.close();
                        await browser.close();
                        return loginUrl;
                    }
                }
                await page.close();
            } catch { /* skip */ }
        } finally {
            await context.close().catch(() => { });
            await browser.close().catch(() => { });
        }

        return null;
    }

    /**
     * Fallback login page discovery using fetch (for non-SPA sites).
     */
    async _discoverLoginPageViaFetch() {
        const paths = ['/login', '/signin', '/auth/login', '/auth/signin', '/sign-in',
            '/account/login', '/user/login', '/admin/login'];
        const baseUrl = this.config.target_url;

        for (const p of paths) {
            try {
                const url = new URL(p, baseUrl).href;
                const resp = await fetch(url, {
                    redirect: 'follow',
                    signal: AbortSignal.timeout(5000),
                });
                if (resp.ok) {
                    const body = await resp.text();
                    if (body.match(/type=["']password["']/i) ||
                        body.match(/login|sign.?in|authenticate/i)) {
                        this.logger?.debug?.(`Discovered login page via fetch: ${url}`);
                        return url;
                    }
                }
            } catch { /* skip */ }
        }
        return null;
    }

    /**
     * Interactively prompt the user for credentials in the terminal.
     * Retries up to 3 times on auth failure.
     * Returns { role, username, password } or null if skipped.
     */
    async _promptForCredentials(loginUrl) {
        // Don't prompt in CI/CD or non-interactive environments
        if (!process.stdin.isTTY) return null;

        // Stop the spinner before prompting (hook set by CLI)
        this._onBeforePrompt?.();

        const chalk = await import('chalk').then(m => m.default).catch(() => ({ hex: () => s => s, dim: s => s, yellow: s => s, green: s => s, red: s => s, bold: s => s }));

        console.log();
        console.log(chalk.yellow('  🔑 Login form detected at: ') + chalk.dim(loginUrl));
        console.log(chalk.dim('     Enter credentials for authenticated scanning, or press Enter to skip.'));

        const MAX_RETRIES = 3;

        for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            console.log();

            if (attempt > 1) {
                console.log(chalk.red(`  ✘ Login failed. Attempt ${attempt}/${MAX_RETRIES} — try again or press Enter to skip.`));
                console.log();
            }

            const username = await this._ask(chalk.dim('  Username/Email: '));
            if (!username) {
                console.log(chalk.dim('  Skipped — scanning unauthenticated.'));
                console.log();
                return null;
            }

            const password = await this._askSecret(chalk.dim('  Password: '));
            if (!password) {
                console.log(chalk.dim('  Skipped — scanning unauthenticated.'));
                console.log();
                return null;
            }

            const role = attempt === 1
                ? (await this._ask(chalk.dim('  Role name (default: user): ')) || 'user')
                : 'user';

            const cred = { role, username, password };

            // Try to actually authenticate with these credentials
            console.log(chalk.dim('  Verifying credentials...'));

            this._browser = this._browser || await BrowserManager.launch({ headless: true });
            const authConfig = this.config.auth || {};
            const state = await this._autoLogin(cred, { ...authConfig, login_url: loginUrl });

            if (state) {
                this.authStates.set(role, state);
                console.log(chalk.green(`  ✔ Login successful as "${role}"`));
                console.log();
                await this._browser.close();
                this._browser = null;
                return cred;
            }

            // Last attempt failed
            if (attempt === MAX_RETRIES) {
                console.log(chalk.red(`  ✘ Login failed after ${MAX_RETRIES} attempts — scanning unauthenticated.`));
                console.log();
                await this._browser.close();
                this._browser = null;
                return null;
            }
        }

        return null;
    }

    /**
     * Prompt for regular text input.
     */
    _ask(prompt) {
        return new Promise((resolve) => {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
            });
            rl.question(prompt, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        });
    }

    /**
     * Prompt for password input with masking (shows * for each character).
     * Uses a muted output stream to prevent raw character echo.
     */
    _askSecret(prompt) {
        return new Promise((resolve) => {
            // Write the prompt
            process.stdout.write(prompt);

            let secret = '';

            // Create a muted writable stream that swallows all output
            const mutedOut = new Writable({
                write(_chunk, _encoding, callback) {
                    callback(); // swallow all output — we handle display manually
                },
            });

            const rl = readline.createInterface({
                input: process.stdin,
                output: mutedOut,
                terminal: true,
            });

            // Listen for keypress events
            process.stdin.setRawMode(true);

            const onData = (buf) => {
                const c = buf.toString();

                if (c === '\n' || c === '\r' || c === '\u0004') {
                    // Enter — done
                    process.stdin.setRawMode(false);
                    process.stdin.removeListener('data', onData);
                    process.stdout.write('\n');
                    rl.close();
                    resolve(secret);
                } else if (c === '\u0003') {
                    // Ctrl+C
                    process.stdin.setRawMode(false);
                    process.stdin.removeListener('data', onData);
                    rl.close();
                    process.exit(0);
                } else if (c === '\u007F' || c === '\b') {
                    // Backspace
                    if (secret.length > 0) {
                        secret = secret.slice(0, -1);
                        process.stdout.write('\b \b');
                    }
                } else if (c.charCodeAt(0) >= 32) {
                    // Printable character only
                    secret += c;
                    process.stdout.write('•');
                }
            };

            process.stdin.on('data', onData);
            process.stdin.resume();
        });
    }

    /**
     * Auto-detect username field selector.
     */
    async _findUsernameField(page) {
        const selectors = [
            'input[type="email"]',
            'input[name="email"]',
            'input[name="username"]',
            'input[name="user"]',
            'input[name="login"]',
            'input[id="email"]',
            'input[id="username"]',
            'input[autocomplete="email"]',
            'input[autocomplete="username"]',
            'input[type="text"]:first-of-type',
        ];
        for (const sel of selectors) {
            const el = await page.$(sel);
            if (el) return sel;
        }
        return null;
    }

    /**
     * Auto-detect password field selector.
     */
    async _findPasswordField(page) {
        const selectors = [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="passwd"]',
            'input[name="pass"]',
            'input[id="password"]',
            'input[autocomplete="current-password"]',
        ];
        for (const sel of selectors) {
            const el = await page.$(sel);
            if (el) return sel;
        }
        return null;
    }

    /**
     * Auto-detect submit button selector.
     */
    async _findSubmitButton(page) {
        const selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button:has-text("Login")',
            'button:has-text("Submit")',
            'form button',
        ];
        for (const sel of selectors) {
            const el = await page.$(sel);
            if (el) return sel;
        }
        return null;
    }

    /**
     * Verify login succeeded using multiple strict signals.
     * Returns true only when strong evidence of successful login exists.
     */
    async _verifyLogin(page, loginUrl) {
        // Wait a moment for SPAs to settle (toasts, redirects, state changes)
        await page.waitForTimeout(1500);

        const currentUrl = page.url();

        // ── FAIL FAST: Check for error indicators ──
        const hasErrors = await page.evaluate(() => {
            const body = document.body?.textContent?.toLowerCase() || '';
            const errorPatterns = [
                'invalid password', 'incorrect password', 'wrong password',
                'invalid credentials', 'invalid email', 'invalid username',
                'authentication failed', 'login failed', 'sign in failed',
                'account not found', 'user not found', 'no account',
                'too many attempts', 'account locked', 'access denied',
                'incorrect email', 'email or password', 'check your credentials',
            ];

            // Check text content for error messages
            if (errorPatterns.some(p => body.includes(p))) return true;

            // Check for visible error/alert elements
            const errorSelectors = [
                '[role="alert"]', '.error', '.error-message', '.alert-error',
                '.alert-danger', '.toast-error', '.notification-error',
                '[class*="error"]', '[class*="Error"]',
                '[data-testid*="error"]', '[aria-invalid="true"]',
            ];
            for (const sel of errorSelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null && el.textContent.trim().length > 0) {
                    return true;
                }
            }
            return false;
        });

        if (hasErrors) {
            this.logger?.debug?.('Login verification: error indicators detected on page');
            return false;
        }

        // ── CHECK 1: Auth cookies/tokens were set ──
        const cookies = await page.context().cookies();
        const authCookieNames = [
            'session', 'sess', 'sid', 'token', 'auth', 'jwt',
            'access_token', 'refresh_token', '_session', 'connect.sid',
            'sb-access-token', 'sb-refresh-token',  // Supabase
            'next-auth', '__session',                // Next.js/Firebase
        ];
        const hasAuthCookies = cookies.some(c =>
            authCookieNames.some(name =>
                c.name.toLowerCase().includes(name)
            )
        );

        // Check localStorage for tokens
        const hasLocalStorageAuth = await page.evaluate(() => {
            const tokenKeys = ['token', 'access_token', 'auth_token', 'jwt', 'session',
                'sb-access-token', 'supabase.auth.token'];
            for (const key of tokenKeys) {
                if (localStorage.getItem(key)) return true;
            }
            // Check all keys for auth-related values
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (k && (k.includes('auth') || k.includes('token') || k.includes('session'))) {
                    const v = localStorage.getItem(k);
                    if (v && v.length > 10) return true;
                }
            }
            return false;
        }).catch(() => false);

        if (hasAuthCookies || hasLocalStorageAuth) {
            this.logger?.debug?.('Login verification: auth cookies/tokens detected');
            return true;
        }

        // ── CHECK 2: URL navigated away from login page ──
        const loginPaths = ['/login', '/signin', '/sign-in', '/auth/login', '/auth/signin'];
        const wasOnLoginPath = loginPaths.some(p => loginUrl.includes(p));
        const isStillOnLoginPath = loginPaths.some(p => currentUrl.includes(p));

        if (wasOnLoginPath && !isStillOnLoginPath && currentUrl !== loginUrl) {
            this.logger?.debug?.(`Login verification: URL changed from ${loginUrl} to ${currentUrl}`);
            return true;
        }

        // ── CHECK 3: Page no longer has password field AND has logged-in UI ──
        const hasPasswordField = await page.$('input[type="password"]');
        if (!hasPasswordField) {
            // Only trust this if we also see logged-in indicators
            const hasLoggedInUI = await page.evaluate(() => {
                // Look for logout buttons/links (text-based search — :has-text isn't valid CSS)
                const buttons = Array.from(document.querySelectorAll('button, a'));
                const hasLogoutBtn = buttons.some(el => {
                    const text = el.textContent?.trim().toLowerCase() || '';
                    return text === 'log out' || text === 'sign out' ||
                        text === 'logout' || text === 'signout' ||
                        text === 'disconnect' || text === 'exit';
                });
                if (hasLogoutBtn) return true;

                // Check for aria-label based logout
                const ariaLogout = document.querySelector(
                    '[aria-label*="logout"], [aria-label*="sign out"], [aria-label*="log out"]'
                );
                if (ariaLogout) return true;

                // Check for avatar/profile menu (common logged-in indicator)
                const avatar = document.querySelector(
                    '[class*="avatar"], [class*="Avatar"], ' +
                    '[data-testid*="avatar"], [data-testid*="user-menu"]'
                );
                if (avatar) return true;

                return false;
            });

            if (hasLoggedInUI) {
                this.logger?.debug?.('Login verification: password field gone + logged-in UI detected');
                return true;
            }
        }

        this.logger?.debug?.('Login verification: no strong evidence of successful login');
        return false;
    }

    /**
     * Parse Set-Cookie headers into Playwright cookie format.
     */
    _parseSetCookieHeaders(headers) {
        const targetUrl = new URL(this.config.target_url);
        return headers.map(header => {
            const parts = header.split(';').map(p => p.trim());
            const [nameValue, ...attrs] = parts;
            const eqIdx = nameValue.indexOf('=');
            const name = nameValue.substring(0, eqIdx);
            const value = nameValue.substring(eqIdx + 1);

            const cookie = {
                name,
                value,
                domain: targetUrl.hostname,
                path: '/',
            };

            for (const attr of attrs) {
                const [key, val] = attr.split('=').map(s => s.trim());
                switch (key.toLowerCase()) {
                    case 'domain': cookie.domain = val; break;
                    case 'path': cookie.path = val; break;
                    case 'httponly': cookie.httpOnly = true; break;
                    case 'secure': cookie.secure = true; break;
                    case 'samesite': cookie.sameSite = val; break;
                }
            }

            return cookie;
        }).filter(c => c.name && c.value);
    }

    /**
     * Get Playwright storageState for a specific role.
     */
    getAuthState(role) {
        const entry = this.authStates.get(role);
        if (!entry) return null;
        // Handle both old (plain state) and new ({ state, postLoginUrl }) shapes
        return entry.state || entry;
    }

    /**
     * Get post-login URL for a specific role (where the user lands after login).
     */
    getPostLoginUrl(role) {
        const entry = this.authStates.get(role);
        return entry?.postLoginUrl || null;
    }

    /**
     * Get links discovered on the post-login page for a specific role.
     */
    getDiscoveredLinks(role) {
        const entry = this.authStates.get(role);
        return entry?.discoveredLinks || [];
    }

    /**
     * Get auth token for a specific role (for API-based agents).
     */
    getAuthToken(role) {
        return this.authTokens.get(role) || null;
    }

    /**
     * Get all authenticated roles.
     */
    get roles() {
        return [...this.authStates.keys()];
    }

    /**
     * Check if any auth is available.
     */
    get isAuthenticated() {
        return this.authStates.size > 0;
    }

    /**
     * Create a Playwright browser context with auth for a given role.
     */
    async createAuthContext(browser, role) {
        const state = this.getAuthState(role);
        if (!state) return null;

        return browser.newContext({
            storageState: state,
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });
    }

    /**
     * Get fetch headers with auth token for a given role.
     */
    getFetchHeaders(role) {
        const tokenInfo = this.authTokens.get(role);
        if (!tokenInfo) return {};
        return {
            'Authorization': `${tokenInfo.type} ${tokenInfo.token}`,
        };
    }
}

export default AuthManager;
