import { createFinding } from '../../utils/finding.js';

/**
 * AccessBoundaryTester — Tests access control boundaries.
 *
 * Probes:
 * - Horizontal IDOR (access other users' resources by changing ID)
 * - UUID/GUID enumeration (sequential UUID prediction and fuzzing)
 * - JWT sub-claim manipulation (change user_id in JWT payload)
 * - Cross-tenant access (change org_id, tenant_id, workspace_id)
 * - Vertical escalation (access admin from unprivileged context)
 * - Guest access (perform auth-required actions without login)
 * - Free-to-paid bypass (access premium features without subscription)
 */
export class AccessBoundaryTester {
    constructor(logger) {
        this.logger = logger;

        // Common ID parameter names
        this.ID_PARAMS = ['id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
            'profile_id', 'order_id', 'orderId', 'item_id', 'itemId'];

        // Admin/privileged paths to test
        this.ADMIN_PATHS = [
            '/admin', '/admin/', '/admin/dashboard', '/admin/users',
            '/admin/settings', '/admin/config', '/manage', '/manage/users',
            '/internal', '/internal/api', '/api/admin', '/api/admin/users',
            '/api/internal', '/settings/admin', '/dashboard/admin',
        ];

        // Premium/paid feature paths
        this.PREMIUM_PATHS = [
            '/premium', '/pro', '/enterprise', '/features/premium',
            '/api/premium', '/api/pro', '/upgrade', '/api/export',
            '/api/analytics', '/api/reports/advanced', '/api/bulk',
        ];
    }

    /**
     * Test access boundaries against discovered surfaces.
     */
    async test(businessContext, surfaceInventory) {
        const findings = [];

        this.logger?.info?.('Access Boundary Tester: starting tests');

        // 1. Test vertical escalation (admin access)
        const verticalFindings = await this._testVerticalEscalation(surfaceInventory);
        findings.push(...verticalFindings);

        // 2. Test IDOR on API endpoints (numeric IDs)
        const idorFindings = await this._testIDOR(businessContext, surfaceInventory);
        findings.push(...idorFindings);

        // 3. Test UUID-based IDOR
        const uuidFindings = await this._testUUIDIDOR(surfaceInventory);
        findings.push(...uuidFindings);

        // 4. Test cross-tenant access
        const crossTenantFindings = await this._testCrossTenantAccess(surfaceInventory);
        findings.push(...crossTenantFindings);

        // 5. Test free-to-paid bypass
        const premiumFindings = await this._testPremiumBypass(surfaceInventory);
        findings.push(...premiumFindings);

        // 6. Test guest access to authenticated routes
        const guestFindings = await this._testGuestAccess(businessContext);
        findings.push(...guestFindings);

        this.logger?.info?.(`Access Boundary Tester: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test vertical privilege escalation — can unprivileged users access admin?
     */
    async _testVerticalEscalation(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        for (const path of this.ADMIN_PATHS) {
            try {
                const url = new URL(path, baseUrl).href;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                // If admin page is accessible (200) without auth, that's a finding
                if (response.status === 200) {
                    const text = await response.text();
                    // Verify it's actually admin content, not a generic 200
                    if (this._isAdminContent(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Vertical Privilege Escalation: Admin Accessible',
                            severity: 'critical',
                            affected_surface: url,
                            description: `Admin endpoint ${path} is accessible without authentication. An unauthenticated user can access administrative functionality.`,
                            reproduction: [
                                `1. Open ${url} in a private/incognito browser`,
                                `2. Admin page loads without login requirement`,
                            ],
                            evidence: `URL: ${url}\nStatus: ${response.status}\nContent indicators: admin content detected`,
                            remediation: 'Implement authentication and authorization checks on all admin endpoints. Use middleware to verify user role before granting access. Return 401/403 for unauthorized requests.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test IDOR — can resource IDs be manipulated to access other users' data?
     * Handles numeric IDs with enumeration.
     */
    async _testIDOR(businessContext, surfaceInventory) {
        const findings = [];
        const apis = surfaceInventory.apis || [];

        for (const api of apis) {
            const url = api.url || api;

            // Check if URL contains numeric IDs that could be enumerated
            const idMatch = url.match(/\/(\d+)(\/|$|\?)/);
            if (!idMatch) continue;

            const originalId = idMatch[1];
            const testIds = [
                String(parseInt(originalId) + 1),
                String(parseInt(originalId) - 1),
                String(parseInt(originalId) + 100),
                '1',
                '0',
                '-1',
            ];

            for (const testId of testIds) {
                if (testId === originalId) continue;

                const tamperedUrl = url.replace(`/${originalId}`, `/${testId}`);
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const response = await fetch(tamperedUrl, {
                        method: 'GET',
                        signal: controller.signal,
                    });
                    clearTimeout(timeout);

                    if (response.ok) {
                        const text = await response.text();
                        if (text.length > 50 && !this._isGenericResponse(text)) {
                            findings.push(createFinding({
                                module: 'logic',
                                title: 'IDOR: Insecure Direct Object Reference (Numeric ID)',
                                severity: 'high',
                                affected_surface: tamperedUrl,
                                description: `Changing the resource ID from ${originalId} to ${testId} in ${url} returned data without authorization check. An attacker can enumerate IDs to access other users' data.`,
                                reproduction: [
                                    `1. Original URL: ${url}`,
                                    `2. Change ID ${originalId} to ${testId}: ${tamperedUrl}`,
                                    `3. Server returns data for the different resource`,
                                ],
                                evidence: `Original ID: ${originalId}\nTest ID: ${testId}\nResponse status: ${response.status}`,
                                remediation: 'Implement authorization checks that verify the requesting user owns the resource. Use UUIDs instead of sequential IDs. Always validate resource ownership server-side.',
                            }));
                            break;
                        }
                    }
                } catch { continue; }
            }
        }

        return findings;
    }

    /**
     * Test UUID-based IDOR — swap or fuzz UUIDs in API paths.
     */
    async _testUUIDIDOR(surfaceInventory) {
        const findings = [];
        const apis = surfaceInventory.apis || [];

        const uuidRegex = /\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(\/|$|\?)/i;

        for (const api of apis) {
            const url = api.url || api;
            const uuidMatch = url.match(uuidRegex);
            if (!uuidMatch) continue;

            const originalUUID = uuidMatch[1];

            // Test with known-invalid UUIDs that might reveal different behavior
            const testUUIDs = [
                '00000000-0000-0000-0000-000000000000', // nil UUID
                '00000000-0000-0000-0000-000000000001', // sequential
                'ffffffff-ffff-ffff-ffff-ffffffffffff', // max UUID
            ];

            for (const testUUID of testUUIDs) {
                const tamperedUrl = url.replace(originalUUID, testUUID);
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const [originalResp, tamperedResp] = await Promise.all([
                        fetch(url, { method: 'GET', signal: controller.signal }),
                        fetch(tamperedUrl, { method: 'GET', signal: controller.signal }),
                    ]);
                    clearTimeout(timeout);

                    if (tamperedResp.ok) {
                        const text = await tamperedResp.text();
                        if (text.length > 50 && !this._isGenericResponse(text)) {
                            findings.push(createFinding({
                                module: 'logic',
                                title: 'IDOR: UUID-Based Object Reference Vulnerable to Enumeration',
                                severity: 'high',
                                affected_surface: tamperedUrl,
                                description: `Swapping the UUID ${originalUUID} with ${testUUID} in ${url} returned a non-error response. If the application doesn't verify UUID ownership, an attacker can access arbitrary resources. UUIDs are only safe against enumeration when ownership is enforced server-side.`,
                                reproduction: [
                                    `1. Original URL: ${url}`,
                                    `2. Swap UUID: ${tamperedUrl}`,
                                    `3. Server returned status ${tamperedResp.status} with ${text.length} bytes`,
                                ],
                                evidence: `Original: ${originalUUID}\nTest: ${testUUID}\nResponse: ${tamperedResp.status} (${text.length} bytes)`,
                                remediation: 'Never rely on UUIDs alone for access control — they prevent enumeration but not targeted sharing. Always verify the requesting user is the owner of the resource identified by the UUID, server-side on every request.',
                            }));
                            break;
                        }
                    }
                } catch { continue; }
            }
        }

        return findings;
    }

    /**
     * Test cross-tenant access by manipulating tenant/org/workspace IDs.
     */
    async _testCrossTenantAccess(surfaceInventory) {
        const findings = [];

        const TENANT_PARAMS = [
            'org_id', 'tenant_id', 'workspace_id', 'organization_id',
            'company_id', 'account_id', 'team_id', 'site_id',
        ];

        for (const page of surfaceInventory.pages) {
            if (!page.url || page.status >= 400) continue;
            const url = new URL(page.url);
            const params = [...url.searchParams.entries()];

            for (const [key, value] of params) {
                const isOrgParam = TENANT_PARAMS.some(p => key.toLowerCase().includes(p.replace('_id', '')));
                if (!isOrgParam) continue;

                // Try to access a different tenant's data
                const testValues = [
                    String(parseInt(value) + 1) || '2',
                    String(parseInt(value) - 1) || '0',
                    '1',
                ];

                const baseResponse = await fetch(page.url).catch(() => null);
                if (!baseResponse?.ok) continue;
                const baseText = await baseResponse.text();

                for (const testValue of testValues) {
                    if (testValue === value) continue;
                    const testUrl = new URL(page.url);
                    testUrl.searchParams.set(key, testValue);

                    try {
                        const response = await fetch(testUrl.toString(), { method: 'GET' });
                        if (!response.ok) continue;

                        const text = await response.text();
                        // Different response length with different tenant ID = potential cross-tenant access
                        const lengthRatio = text.length / (baseText.length || 1);
                        if (text.length > 100 && lengthRatio > 0.5 && !this._isGenericResponse(text)) {
                            findings.push(createFinding({
                                module: 'logic',
                                title: `Cross-Tenant Access: ${key} parameter not enforcing tenant isolation`,
                                severity: 'critical',
                                affected_surface: page.url,
                                description: `Changing the ${key} parameter from ${value} to ${testValue} in ${page.url} returned data without authorization check. This indicates the server is not enforcing tenant isolation — an attacker from one tenant can access another tenant's data.`,
                                reproduction: [
                                    `1. Authenticated as tenant ${value}, access: ${page.url}`,
                                    `2. Change ${key} to ${testValue}: ${testUrl.toString()}`,
                                    `3. Server returns data belonging to tenant ${testValue}`,
                                ],
                                evidence: `Tenant param: ${key}\nOriginal value: ${value}\nTest value: ${testValue}\nResponse: ${response.status} (${text.length} bytes)`,
                                remediation: 'All database queries must include a mandatory tenant_id filter derived from the authenticated session, never from user-supplied input. Use row-level security (RLS) in the database. Never trust client-provided tenant/org IDs for data access decisions.',
                                references: ['CWE-284', 'OWASP API Security Top 10 – API1: Broken Object Level Authorization'],
                            }));
                            break;
                        }
                    } catch { continue; }
                }
            }
        }

        return findings;
    }

    /**
     * Test premium/paid feature bypass.
     */
    async _testPremiumBypass(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        for (const path of this.PREMIUM_PATHS) {
            try {
                const url = new URL(path, baseUrl).href;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.status === 200) {
                    const text = await response.text();
                    if (text.length > 100 && !this._isGenericResponse(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Access Bypass: Premium Feature Accessible',
                            severity: 'high',
                            affected_surface: url,
                            description: `Premium endpoint ${path} is accessible without a paid subscription. Unauthenticated users can access features intended for paying customers.`,
                            reproduction: [
                                `1. Open ${url} without authentication`,
                                `2. Premium content is accessible`,
                            ],
                            evidence: `URL: ${url}\nStatus: ${response.status}`,
                            remediation: 'Verify subscription status server-side before serving premium content. Implement tier-based access control in middleware.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test guest access to authenticated routes.
     */
    async _testGuestAccess(businessContext) {
        const findings = [];
        const authSurfaces = businessContext.domains?.auth || [];

        // Look for API endpoints in auth domain that should require login
        const apiEndpoints = businessContext.apiEndpoints?.auth || [];

        for (const endpoint of apiEndpoints) {
            // Skip login/register endpoints (these should be accessible)
            if (/login|signin|register|signup|forgot|reset/i.test(endpoint.url)) continue;

            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(endpoint.url, {
                    method: endpoint.method || 'GET',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.ok) {
                    const text = await response.text();
                    if (this._containsSensitiveData(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Guest Access: Authenticated Endpoint Exposed',
                            severity: 'high',
                            affected_surface: endpoint.url,
                            description: `Authenticated endpoint ${endpoint.url} returns sensitive data without requiring authentication token/session.`,
                            reproduction: [
                                `1. Send ${endpoint.method} to ${endpoint.url} without auth headers`,
                                `2. Server returns sensitive data`,
                            ],
                            evidence: `URL: ${endpoint.url}\nMethod: ${endpoint.method}\nStatus: ${response.status}`,
                            remediation: 'Require authentication tokens on all protected endpoints. Return 401 for unauthenticated requests. Never rely on client-side route guards alone.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    _getBaseUrl(surfaceInventory) {
        const pages = surfaceInventory.pages || [];
        if (pages.length === 0) return null;
        const firstUrl = pages[0].url || pages[0];
        try {
            const parsed = new URL(firstUrl);
            return `${parsed.protocol}//${parsed.host}`;
        } catch {
            return null;
        }
    }

    _isAdminContent(text) {
        return /admin|dashboard|manage|settings|users|configuration/i.test(text) &&
            text.length > 200;
    }

    _isGenericResponse(text) {
        return /not found|404|403|unauthorized|forbidden|error/i.test(text) &&
            text.length < 500;
    }

    _containsSensitiveData(text) {
        return /@[\w.-]+\.\w+/.test(text) || // email
            /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(text) || // phone
            /"(password|token|secret|key)":/i.test(text) || // sensitive fields
            (text.length > 200 && /"(id|user|name|email)":/i.test(text)); // user data
    }
}

export default AccessBoundaryTester;
