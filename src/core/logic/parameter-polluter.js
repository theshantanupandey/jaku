import { createFinding } from '../../utils/finding.js';

/**
 * ParameterPolluter — Tests for HTTP Parameter Pollution (HPP) vulnerabilities.
 *
 * HPP occurs when an application receives multiple values for the same parameter
 * and uses an unexpected one. This can bypass security checks, WAF rules,
 * or access controls depending on which parameter value the backend actually uses.
 *
 * Attack variants:
 * 1. URL query string duplication: ?user_id=1&user_id=admin
 * 2. Body + Query collision: POST body user_id=1, URL ?user_id=admin
 * 3. Array notation: ?user_id[]=1&user_id[]=admin
 * 4. Verb tampering for bypass: change GET → POST or HEAD
 * 5. Content-Type confusion: send JSON payload as form-encoded
 */
export class ParameterPolluter {
    constructor(logger) {
        this.logger = logger;

        // High-value parameters to test for pollution
        this.SENSITIVE_PARAMS = [
            { name: 'user_id', testValues: ['0', 'null', 'undefined', '../admin', 'admin', '1 OR 1=1'] },
            { name: 'role', testValues: ['admin', 'superuser', 'root', 'administrator'] },
            { name: 'admin', testValues: ['true', '1', 'yes', 'on'] },
            { name: 'is_admin', testValues: ['true', '1'] },
            { name: 'account_id', testValues: ['0', '-1', 'null', '../'] },
            { name: 'token', testValues: ['undefined', 'null', '', '0'] },
            { name: 'redirect', testValues: ['https://evil.com', '//evil.com', '/\\/evil.com'] },
            { name: 'callback', testValues: ['alert', 'console.log', 'https://evil.com?'] },
            { name: 'action', testValues: ['delete', 'admin', 'debug', 'export'] },
            { name: 'debug', testValues: ['true', '1', 'yes'] },
        ];
    }

    async pollute(businessContext, surfaceInventory) {
        const findings = [];

        for (const page of surfaceInventory.pages) {
            if (!page.url || page.status >= 400) continue;
            const url = new URL(page.url);
            const existingParams = [...url.searchParams.keys()];

            // Test 1: Duplicate existing parameters with escalated values
            for (const param of existingParams) {
                const original = url.searchParams.get(param);
                const result = await this._testDuplication(url, param, original);
                if (result) findings.push(result);
            }

            // Test 2: Inject sensitive parameters that aren't in the URL
            for (const { name, testValues } of this.SENSITIVE_PARAMS) {
                if (existingParams.includes(name)) continue;
                const result = await this._testInjection(url, name, testValues);
                if (result) findings.push(result);
            }
        }

        // Test 3: HTTP verb tampering on API endpoints
        for (const page of surfaceInventory.pages.slice(0, 15)) {
            const result = await this._testVerbTamper(page.url);
            if (result) findings.push(result);
        }

        this.logger?.info?.(`Parameter Polluter: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test parameter duplication: ?param=original&param=escalated
     * Measure if behavior changes when the param appears twice.
     */
    async _testDuplication(url, param, original) {
        try {
            // Baseline request (normal param)
            const baseResponse = await this._fetchWithTimeout(url.toString());
            if (!baseResponse) return null;

            // Polluted request: append escalated value
            const pollutedUrl = new URL(url.toString());
            // Append a second value by manipulating the string directly
            const pollutedStr = pollutedUrl.toString() + `&${param}=admin&${param}=0&${param}=undefined`;

            const pollutedResponse = await this._fetchWithTimeout(pollutedStr);
            if (!pollutedResponse) return null;

            // Compare: different status code or significantly different response size indicates different handling
            const statusDiff = baseResponse.status !== pollutedResponse.status;
            const sizeDiff = Math.abs(baseResponse.body.length - pollutedResponse.body.length) > 200;
            const newPrivileges = /admin|dashboard|user.*list|export|settings/i.test(pollutedResponse.body) &&
                !/admin|dashboard|user.*list|export|settings/i.test(baseResponse.body);

            if (statusDiff || newPrivileges) {
                return createFinding({
                    module: 'logic',
                    title: `HTTP Parameter Pollution: "${param}" behavior change with duplicate values`,
                    severity: newPrivileges ? 'high' : 'medium',
                    affected_surface: url.toString(),
                    description: `The parameter "${param}" at ${url.toString()} behaves differently when submitted with duplicate (polluted) values. The baseline response had status ${baseResponse.status}, but the polluted request (with ?${param}=${original}&${param}=admin) returned status ${pollutedResponse.status}. This may indicate that the server uses a different copy of the parameter than expected, potentially bypassing access controls or validation.`,
                    reproduction: [
                        `1. Baseline: GET ${url.toString()}`,
                        `2. Polluted: GET ${pollutedStr}`,
                        `3. Response differs: baseline ${baseResponse.status} → polluted ${pollutedResponse.status}`,
                    ],
                    evidence: `Param: ${param}\nBaseline status: ${baseResponse.status}\nPolluted status: ${pollutedResponse.status}\nSize diff: ${Math.abs(baseResponse.body.length - pollutedResponse.body.length)} bytes`,
                    remediation: 'Use a strict parameter parsing strategy: reject requests with duplicate parameters, or explicitly define which value to use (first or last). Apply the same strategy consistently across all framework layers (web server, app framework, middleware).',
                    references: ['https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Parameter_Pollution_Prevention_Cheat_Sheet.html', 'CWE-235'],
                });
            }
        } catch { /* skip */ }
        return null;
    }

    /**
     * Test injecting new sensitive parameters into URLs that don't already have them.
     */
    async _testInjection(url, paramName, testValues) {
        try {
            const baseResponse = await this._fetchWithTimeout(url.toString());
            if (!baseResponse || baseResponse.status >= 400) return null;

            for (const value of testValues) {
                const testUrl = new URL(url.toString());
                testUrl.searchParams.set(paramName, value);

                const response = await this._fetchWithTimeout(testUrl.toString());
                if (!response) continue;

                // Look for clear indicators of privilege change
                const privilegeGranted =
                    (response.status < 400 && baseResponse.status >= 400) || // Became accessible
                    (/admin|dashboard|panel|settings|debug.*true|is_admin.*true/i.test(response.body) &&
                        !/admin|dashboard|panel|settings/i.test(baseResponse.body));

                if (privilegeGranted) {
                    return createFinding({
                        module: 'logic',
                        title: `Parameter Injection: ?${paramName}=${value} grants elevated access`,
                        severity: 'critical',
                        affected_surface: url.toString(),
                        description: `Adding the parameter "?${paramName}=${value}" to ${url.toString()} appears to grant elevated access or change application behavior in an unexpected way. The server accepted the parameter and changed its response significantly. This suggests the parameter is processed by the backend without proper authorization checks.`,
                        reproduction: [
                            `1. Baseline: GET ${url.toString()} — status ${baseResponse.status}`,
                            `2. Injected: GET ${testUrl.toString()} — status ${response.status}`,
                            '3. Application behavior changed',
                        ],
                        evidence: `Injected: ?${paramName}=${value}\nBaseline status: ${baseResponse.status}\nInjected status: ${response.status}`,
                        remediation: 'Never use query parameters alone to determine authorization or privileges. All access control decisions must be based on server-side session state and validated credentials, never on client-supplied parameters.',
                        references: ['CWE-235', 'https://owasp.org/www-project-top-ten/'],
                    });
                }
            }
        } catch { /* skip */ }
        return null;
    }

    /**
     * Test HTTP verb tampering — some apps restrict DELETE but allow POST with ?_method=DELETE.
     */
    async _testVerbTamper(url) {
        if (!url) return null;
        try {
            const methods = ['DELETE', 'PUT', 'PATCH'];
            const baseGet = await this._fetchWithTimeout(url.toString(), 'GET');
            if (!baseGet) return null;

            for (const method of methods) {
                const response = await this._fetchWithTimeout(url.toString(), method);
                if (!response) continue;

                // If DELETE/PUT succeeds (2xx) on a page that GETs normally, flag it
                if (response.status < 300 && baseGet.status < 400) {
                    return createFinding({
                        module: 'logic',
                        title: `HTTP Verb Tampering: ${method} accepted at ${new URL(url).pathname}`,
                        severity: 'high',
                        affected_surface: url,
                        description: `The endpoint ${url} accepts ${method} requests without apparent authorization restrictions. If this endpoint supports state-changing operations via ${method}, it may be exploitable without CSRF protection (since CORS does protect non-simple methods, but SPA apps with CORS misconfiguration may still be vulnerable).`,
                        reproduction: [
                            `1. Send ${method} ${url}`,
                            `2. Server responds with ${response.status} (success)`,
                        ],
                        evidence: `GET status: ${baseGet.status}\n${method} status: ${response.status}`,
                        remediation: 'Implement strict HTTP method validation. Return 405 Method Not Allowed for unsupported verbs on each endpoint. Use server framework routing to explicitly define allowed methods per route.',
                        references: ['https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'],
                    });
                }
            }
        } catch { /* skip */ }
        return null;
    }

    async _fetchWithTimeout(url, method = 'GET') {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        try {
            const response = await fetch(url, {
                method,
                redirect: 'manual',
                signal: controller.signal,
            });
            const body = await response.text().catch(() => '');
            return { status: response.status, body };
        } catch {
            return null;
        } finally {
            clearTimeout(timeout);
        }
    }
}

export default ParameterPolluter;
