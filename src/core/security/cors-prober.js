import { createFinding } from '../../utils/finding.js';

/**
 * CORSProber — Tests for Cross-Origin Resource Sharing misconfigurations.
 *
 * Common misconfigs:
 * 1. Wildcard with credentials — Access-Control-Allow-Origin: * + Allow-Credentials: true (impossible per spec, but some servers do it anyway)
 * 2. Arbitrary origin reflection — server mirrors back whatever Origin: header is sent
 * 3. Null origin accepted — Origin: null bypasses same-origin policy
 * 4. Pre-flight bypass — complex request proceeds without OPTIONS check
 * 5. Subdomain wildcard — *.yourapp.com allows evil.yourapp.com (subdomain takeover vector)
 * 6. Trusted domain substring match — trusts "evil-yourapp.com" because it contains "yourapp.com"
 */
export class CORSProber {
    constructor(logger) {
        this.logger = logger;
    }

    async probe(surfaceInventory) {
        const findings = [];
        const tested = new Set();

        // Test API endpoints and key pages
        const targets = [
            ...surfaceInventory.pages.filter(p => p.status < 400),
            ...(surfaceInventory.apis || []),
        ];

        for (const target of targets) {
            const url = target.url || target;
            if (!url || tested.has(url)) continue;
            tested.add(url);

            try {
                const result = await this._testCORS(url);
                if (result) findings.push(result);
            } catch (err) {
                this.logger?.debug?.(`CORS probe failed for ${url}: ${err.message}`);
            }
        }

        this.logger?.info?.(`CORS Prober: found ${findings.length} misconfigurations`);
        return findings;
    }

    async _testCORS(url) {
        const testOrigins = [
            { origin: 'https://evil.attacker.com', label: 'arbitrary external origin' },
            { origin: 'null', label: 'null origin' },
            { origin: `https://evil.${new URL(url).hostname}`, label: 'evil subdomain of target' },
            { origin: `https://evil-${new URL(url).hostname}`, label: 'substring match bypass' },
        ];

        for (const { origin, label } of testOrigins) {
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 10000);

                const response = await fetch(url, {
                    method: 'GET',
                    headers: { 'Origin': origin },
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                const acao = response.headers.get('access-control-allow-origin');
                const acac = response.headers.get('access-control-allow-credentials');

                if (!acao) continue;

                // Check 1: Arbitrary origin reflected
                if (acao === origin || acao === '*') {
                    const withCredentials = acac === 'true';
                    const severity = withCredentials ? 'critical' : (acao === '*' ? 'low' : 'high');

                    if (withCredentials && acao === '*') continue; // Impossible per spec, browser blocks it

                    return createFinding({
                        module: 'security',
                        title: `CORS Misconfiguration: ${label}`,
                        severity,
                        affected_surface: url,
                        description: `The server at ${url} reflects a ${label} in its CORS response header (Access-Control-Allow-Origin: ${acao}${withCredentials ? ', Access-Control-Allow-Credentials: true' : ''}). ${withCredentials
                            ? 'This is a CRITICAL misconfiguration — credentialed cross-origin requests from any origin are permitted, enabling session hijacking from any website.'
                            : 'This allows cross-origin reads from any origin.'}`,
                        reproduction: [
                            `1. Send a request to ${url} with header: Origin: ${origin}`,
                            `2. Response includes: Access-Control-Allow-Origin: ${acao}`,
                            withCredentials ? '3. Access-Control-Allow-Credentials: true is also present' : '',
                            `4. Any website on the internet can now read the response with ${withCredentials ? 'user credentials' : 'no credentials'}`,
                        ].filter(Boolean),
                        evidence: `Request Origin: ${origin}\nResponse ACAO: ${acao}\nResponse ACAC: ${acac || 'not set'}`,
                        remediation: 'Only allow specific, known origins in CORS policy. Never reflect the request Origin back directly. Never combine Access-Control-Allow-Credentials: true with a wildcard or arbitrary origin. Maintain an explicit allowlist of trusted origins.',
                        references: [
                            'https://portswigger.net/web-security/cors',
                            'https://owasp.org/www-community/attacks/CORS_RequestPreflightScrutiny',
                            'CWE-942',
                        ],
                    });
                }
            } catch { /* continue to next origin */ }
        }

        // Check pre-flight bypass: send complex request without OPTIONS
        await this._testPreflightBypass(url, findings);

        return null;
    }

    async _testPreflightBypass(url, findings) {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 8000);

            // Complex request that SHOULD trigger pre-flight but might not
            const response = await fetch(url, {
                method: 'PUT',
                headers: {
                    'Origin': 'https://evil.attacker.com',
                    'Content-Type': 'application/json',
                    'X-Custom-Header': 'jaku-test',
                },
                body: JSON.stringify({ test: 'preflight-bypass' }),
                signal: controller.signal,
            });
            clearTimeout(timeout);

            const acao = response.headers.get('access-control-allow-origin');
            if (acao === 'https://evil.attacker.com' || acao === '*') {
                findings.push(createFinding({
                    module: 'security',
                    title: 'CORS Pre-flight Bypass: Complex requests allowed from arbitrary origin',
                    severity: 'high',
                    affected_surface: url,
                    description: `${url} accepts complex cross-origin PUT requests from arbitrary origins without requiring a proper OPTIONS pre-flight check. This allows attackers to make state-changing requests on behalf of authenticated users from any origin.`,
                    reproduction: [
                        `1. Send PUT ${url} with Origin: https://evil.attacker.com`,
                        `2. Server responds with Access-Control-Allow-Origin: ${acao}`,
                        '3. Complex cross-origin request succeeds without pre-flight',
                    ],
                    evidence: `Method: PUT | Origin: https://evil.attacker.com | Response ACAO: ${acao}`,
                    remediation: 'Ensure all state-changing endpoints trigger and validate CORS pre-flight requests. On the server side, explicitly validate the Origin header against an allowlist for all methods other than GET/HEAD.',
                    references: ['https://portswigger.net/web-security/cors'],
                }));
            }
        } catch { /* ignore */ }
    }
}

export default CORSProber;
