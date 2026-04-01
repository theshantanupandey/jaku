import { createFinding } from '../../utils/finding.js';

/**
 * PrototypePollutionScanner — Tests for JavaScript prototype pollution vulnerabilities.
 *
 * Prototype pollution allows attackers to add properties to the global
 * Object.prototype, which are then inherited by all objects, potentially
 * causing RCE, access control bypass, or DoS in Node.js applications.
 *
 * Test vectors:
 * - URL query parameters: ?__proto__[admin]=true
 * - JSON body: {"__proto__":{"admin":true}}
 * - Nested paths: ?constructor[prototype][admin]=true
 * - URL path segments: /__proto__/admin
 */
export class PrototypePollutionScanner {
    constructor(logger) {
        this.logger = logger;

        // Pollution vectors to test
        this.URL_VECTORS = [
            { param: '__proto__[polluted]', value: 'jaku_pp_test', label: 'Direct __proto__ param' },
            { param: '__proto__[admin]', value: 'true', label: '__proto__[admin] escalation' },
            { param: 'constructor[prototype][polluted]', value: 'jaku_pp_test', label: 'Constructor prototype' },
            { param: 'constructor.prototype.polluted', value: 'jaku_pp_test', label: 'Dot notation constructor' },
        ];

        this.JSON_VECTORS = [
            { body: { '__proto__': { 'polluted': 'jaku_pp_test', 'admin': true } }, label: 'JSON __proto__ key' },
            { body: { 'constructor': { 'prototype': { 'polluted': 'jaku_pp_test' } } }, label: 'JSON constructor.prototype' },
            { body: [{ '__proto__': { 'polluted': 'jaku_pp_test' } }], label: 'Array __proto__ element' },
        ];
    }

    async scan(surfaceInventory) {
        const findings = [];
        const tested = new Set();

        // Test API endpoints and forms
        const targets = surfaceInventory.pages.filter(p => p.status < 400).slice(0, 20);

        for (const target of targets) {
            if (tested.has(target.url)) continue;
            tested.add(target.url);

            // URL parameter pollution
            const urlFinding = await this._testURLPollution(target.url);
            if (urlFinding) findings.push(urlFinding);

            // JSON body pollution (for API endpoints)
            const jsonFinding = await this._testJSONPollution(target.url);
            if (jsonFinding) findings.push(jsonFinding);
        }

        this.logger?.info?.(`Prototype Pollution: found ${findings.length} issues`);
        return findings;
    }

    async _testURLPollution(url) {
        for (const vector of this.URL_VECTORS) {
            try {
                const testUrl = new URL(url);
                testUrl.searchParams.set(vector.param, vector.value);

                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 8000);

                const response = await fetch(testUrl.toString(), {
                    method: 'GET',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (!response.ok) continue;
                const text = await response.text();

                // Heuristic: if the pollution key/value appears in a JSON response, it may indicate reflection
                if (text.includes('jaku_pp_test') || text.includes('"admin":true') || text.includes('"polluted"')) {
                    return createFinding({
                        module: 'security',
                        title: `Prototype Pollution via URL Parameter: ${vector.label}`,
                        severity: 'high',
                        affected_surface: url,
                        description: `The endpoint reflects prototype pollution payloads injected via URL parameters. The vector "${vector.param}=${vector.value}" appears in the response, suggesting the server merges query parameters into objects without sanitizing prototype chain keys. In Node.js applications (lodash.merge, jQuery.extend, etc.), this can lead to global object corruption, access control bypass, or Remote Code Execution.`,
                        reproduction: [
                            `1. Send GET ${testUrl.toString()}`,
                            '2. Server reflects pollution key in response',
                            '3. If server uses a vulnerable merge operation, Object.prototype is now polluted',
                        ],
                        evidence: `URL: ${testUrl.toString()}\nResponse contained: ${text.substring(0, 300)}`,
                        remediation: 'Sanitize all object keys before using them as property names. Use Object.hasOwnProperty checks. Use Object.create(null) for merge targets. Update lodash >= 4.17.21, jQuery >= 3.4.0. Use flat-param libraries that reject prototype chain keys.',
                        references: [
                            'https://portswigger.net/web-security/prototype-pollution',
                            'CWE-1321',
                            'https://snyk.io/vuln/SNYK-JS-LODASH-567746',
                        ],
                    });
                }
            } catch { /* continue */ }
        }
        return null;
    }

    async _testJSONPollution(url) {
        for (const vector of this.JSON_VECTORS) {
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 8000);

                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(vector.body),
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (!response.ok && response.status !== 422) continue;
                const text = await response.text();

                if (text.includes('jaku_pp_test') || (text.includes('admin') && text.includes('true'))) {
                    return createFinding({
                        module: 'security',
                        title: `Prototype Pollution via JSON Body: ${vector.label}`,
                        severity: 'critical',
                        affected_surface: url,
                        description: `The endpoint accepts JSON bodies containing "__proto__" or "constructor.prototype" keys and appears to process them without sanitization. A successful prototype pollution attack on the server can corrupt the Node.js runtime's Object prototype, enabling privilege escalation or code execution.`,
                        reproduction: [
                            `1. POST to ${url} with body: ${JSON.stringify(vector.body).substring(0, 150)}`,
                            '2. Server processes the __proto__ key',
                            '3. Check if admin endpoints become accessible: GET /admin',
                        ],
                        evidence: `Body: ${JSON.stringify(vector.body)}\nResponse: ${text.substring(0, 300)}`,
                        remediation: 'Never use prototype-unsafe merge functions (lodash.merge pre-4.17.21, $.extend deep, Object.assign with user input as a source). Use a JSON schema validator that rejects __proto__ keys. Filter out __proto__, constructor, and prototype keys from all incoming JSON at the API gateway layer.',
                        references: [
                            'https://portswigger.net/web-security/prototype-pollution/server-side',
                            'CWE-1321',
                        ],
                    });
                }
            } catch { /* continue */ }
        }
        return null;
    }
}

export default PrototypePollutionScanner;
