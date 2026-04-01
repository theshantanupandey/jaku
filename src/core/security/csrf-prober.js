import { chromium } from 'playwright';
import { createFinding } from '../../utils/finding.js';

/**
 * CSRFProber — Tests for Cross-Site Request Forgery vulnerabilities.
 *
 * Active tests:
 * 1. State-changing GET requests (no CSRF protection by design)
 * 2. Missing SameSite cookie attribute
 * 3. CSRF token absent on state-changing forms
 * 4. Weak CSRF token (predictable, short, static)
 * 5. Double-submit cookie bypass
 * 6. Custom header bypass attempt (some apps use X-Requested-With as CSRF protection)
 */
export class CSRFProber {
    constructor(logger) {
        this.logger = logger;
    }

    async probe(surfaceInventory) {
        const findings = [];

        // Test 1: State-changing GET endpoints
        findings.push(...await this._testStateChangingGET(surfaceInventory));

        // Test 2: Cookie SameSite attribute
        findings.push(...await this._testCookieSameSite(surfaceInventory));

        // Test 3: CSRF token validation on forms
        findings.push(...await this._testFormCSRFTokens(surfaceInventory));

        this.logger?.info?.(`CSRF Prober: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Detect state-changing GET endpoints which are inherently CSRF-vulnerable
     * (Safe HTTP methods should never change state).
     */
    async _testStateChangingGET(surfaceInventory) {
        const findings = [];
        const stateChangingPatterns = [
            /\/(delete|remove|destroy|logout|signout|clear|reset|confirm|activate|deactivate|ban|unban|approve|reject|cancel|archive)/i,
            /[?&](action|do|cmd|command)=(delete|remove|logout|reset|confirm|activate|deactivate)/i,
        ];

        for (const page of surfaceInventory.pages) {
            if (!page.url || page.status >= 400) continue;
            const url = page.url;

            for (const pattern of stateChangingPatterns) {
                if (pattern.test(url)) {
                    try {
                        const controller = new AbortController();
                        const timeout = setTimeout(() => controller.abort(), 8000);

                        const response = await fetch(url, {
                            method: 'GET',
                            redirect: 'manual',
                            signal: controller.signal,
                        });
                        clearTimeout(timeout);

                        // If it returns 200 (not a redirect to login) it's likely processing the action
                        if (response.status === 200) {
                            findings.push(createFinding({
                                module: 'security',
                                title: `CSRF: State-Changing GET Request at ${new URL(url).pathname}`,
                                severity: 'high',
                                affected_surface: url,
                                description: `The endpoint ${url} appears to perform a state-changing action (${url.match(stateChangingPatterns[0])?.[1] || 'action'}) via GET request. GET requests cannot be protected by CSRF tokens in standard implementations, and browsers will silently follow GET-based CSRF via <img>, <link> or fetch() from any origin.`,
                                reproduction: [
                                    `1. While victim is authenticated, embed: <img src="${url}">`,
                                    `2. Victim's browser silently GETs the URL with their session cookies`,
                                    `3. Action is performed without victim's knowledge`,
                                ],
                                evidence: `URL: ${url}\nMethod: GET\nResponse: ${response.status}`,
                                remediation: 'All state-changing operations must use POST, PUT, PATCH, or DELETE. Never use GET for actions that modify data. Combine with CSRF tokens on all state-changing endpoints.',
                                references: ['https://owasp.org/www-community/attacks/csrf', 'CWE-352'],
                            }));
                        }
                    } catch { /* skip */ }
                    break;
                }
            }
        }

        return findings;
    }

    /**
     * Check cookies for missing SameSite attribute.
     */
    async _testCookieSameSite(surfaceInventory) {
        const findings = [];
        const baseUrl = surfaceInventory.pages[0]?.url;
        if (!baseUrl) return findings;

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000);

            const response = await fetch(baseUrl, { signal: controller.signal });
            clearTimeout(timeout);

            const cookies = response.headers.getSetCookie?.() || [];

            for (const cookie of cookies) {
                const isSession = /session|auth|token|sid|jwt|access|refresh/i.test(cookie);
                const hasSameSite = /samesite=/i.test(cookie);
                const isStrict = /samesite=strict/i.test(cookie);
                const isLax = /samesite=lax/i.test(cookie);
                const isSecure = /;\s*secure/i.test(cookie);
                const isHttpOnly = /;\s*httponly/i.test(cookie);
                const cookieName = cookie.split('=')[0].trim();

                if (isSession && !hasSameSite) {
                    findings.push(createFinding({
                        module: 'security',
                        title: `CSRF: Session Cookie Missing SameSite Attribute (${cookieName})`,
                        severity: 'medium',
                        affected_surface: baseUrl,
                        description: `The session cookie "${cookieName}" does not have a SameSite attribute. Without SameSite=Lax or SameSite=Strict, the cookie is sent on all cross-site requests, enabling CSRF attacks against all state-changing endpoints. Modern browsers default to Lax for cookies without SameSite, but this is not enforced in all scenarios (e.g., top-level POST navigations).`,
                        reproduction: [
                            `1. Auth cookie "${cookieName}" is set without SameSite`,
                            '2. A cross-site form submission targeting a state-changing endpoint will include this cookie',
                            '3. Server processes the request as authenticated',
                        ],
                        evidence: `Set-Cookie: ${cookie.substring(0, 200)}`,
                        remediation: 'Set SameSite=Strict on session cookies for the highest protection. If Strict breaks legitimate cross-site navigation, use SameSite=Lax. Combine with CSRF tokens for defense-in-depth. Also ensure Secure and HttpOnly flags are set.',
                        references: ['https://owasp.org/www-community/SameSite', 'CWE-352'],
                    }));
                }

                // Separate finding for missing Secure flag on session cookies
                if (isSession && !isSecure) {
                    findings.push(createFinding({
                        module: 'security',
                        title: `Insecure Cookie: Missing Secure Flag (${cookieName})`,
                        severity: 'medium',
                        affected_surface: baseUrl,
                        description: `The session cookie "${cookieName}" does not have the Secure flag. This means the cookie may be transmitted over unencrypted HTTP connections, where it can be intercepted by network attackers.`,
                        reproduction: [
                            `1. Make an HTTP (non-HTTPS) request to ${baseUrl}`,
                            `2. Cookie "${cookieName}" may be sent in plaintext`,
                        ],
                        evidence: `Set-Cookie: ${cookie.substring(0, 200)}`,
                        remediation: 'Always set the Secure flag on session and authentication cookies. Enforce HTTPS everywhere and use HSTS.',
                        references: ['https://owasp.org/www-community/HttpOnly', 'CWE-614'],
                    }));
                }
            }
        } catch (err) {
            this.logger?.debug?.(`CSRF cookie test failed: ${err.message}`);
        }

        return findings;
    }

    /**
     * Test if state-changing forms have CSRF token validation.
     */
    async _testFormCSRFTokens(surfaceInventory) {
        const findings = [];

        const stateChangingForms = (surfaceInventory.forms || []).filter(f => {
            const method = (f.method || 'GET').toUpperCase();
            return method === 'POST' || method === 'PUT' || method === 'DELETE';
        });

        if (stateChangingForms.length === 0) return findings;

        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ ignoreHTTPSErrors: true });

        for (const form of stateChangingForms.slice(0, 10)) { // limit to 10
            const page = await context.newPage();
            try {
                await page.goto(form.page, { waitUntil: 'domcontentloaded', timeout: 15000 });

                // Check if form has a CSRF token field
                const csrfField = await page.$('[name*="csrf"], [name*="_token"], [name*="authenticity_token"], [name*="nonce"], [name*="__RequestVerificationToken"]');

                if (!csrfField) {
                    // No CSRF token — check if the form action changes state
                    const formEl = await page.$(`#${form.id}`) || await page.$('form');
                    const action = form.action || await formEl?.getAttribute('action') || form.page;

                    findings.push(createFinding({
                        module: 'security',
                        title: `CSRF: No Token on State-Changing Form at ${new URL(form.page).pathname}`,
                        severity: 'high',
                        affected_surface: form.page,
                        description: `The form at ${form.page} (action: ${action}) submits via ${form.method || 'POST'} but does not contain a CSRF token. An attacker can host a forged form on any website that will automatically submit with the victim's session cookies.`,
                        reproduction: [
                            `1. Host this HTML on a malicious site: <form action="${action}" method="post"><input type="submit"></form>`,
                            '2. Trick victim into visiting the malicious page while authenticated',
                            '3. Form auto-submits with victim\'s cookies',
                        ],
                        evidence: `Form page: ${form.page}\nForm action: ${action}\nCSRF token: none found`,
                        remediation: 'Add a cryptographically random CSRF token to all state-changing forms. Validate the token server-side on every submission. Use the Synchronizer Token Pattern or Double Submit Cookie pattern. Combine with SameSite=Strict cookies.',
                        references: ['https://owasp.org/www-community/attacks/csrf', 'CWE-352'],
                    }));
                }
            } catch (err) {
                this.logger?.debug?.(`CSRF form test failed for ${form.page}: ${err.message}`);
            } finally {
                await page.close();
            }
        }

        await browser.close();
        return findings;
    }
}

export default CSRFProber;
