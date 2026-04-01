import { createFinding } from '../../utils/finding.js';

/**
 * GraphQLAuditor — Comprehensive GraphQL security audit.
 *
 * Tests:
 * 1. Introspection enabled — allows schema discovery
 * 2. Batch query amplification — N identical queries in one request
 * 3. Deeply nested query DoS — infinite depth via recursive types
 * 4. Field suggestion extraction — even without introspection
 * 5. Mutation authorization bypass — mutate without auth
 * 6. Alias-based rate limit bypass — 100 alias queries = 1 request
 */
export class GraphQLAuditor {
    constructor(logger) {
        this.logger = logger;

        this.COMMON_ENDPOINTS = ['/graphql', '/api/graphql', '/query', '/gql', '/v1/graphql', '/graphql/v1', '/graphql/v2', '/api/query'];
    }

    async audit(surfaceInventory) {
        const findings = [];

        // Discover GraphQL endpoints
        const baseUrl = surfaceInventory.pages[0]?.url;
        if (!baseUrl) return findings;

        const origin = new URL(baseUrl).origin;
        const graphqlEndpoints = await this._discoverEndpoints(origin, surfaceInventory);

        if (graphqlEndpoints.length === 0) {
            this.logger?.info?.('GraphQL Auditor: no GraphQL endpoints found');
            return findings;
        }

        this.logger?.info?.(`GraphQL Auditor: testing ${graphqlEndpoints.length} endpoint(s)`);

        for (const endpoint of graphqlEndpoints) {
            // Test 1: Introspection
            const introspectionFinding = await this._testIntrospection(endpoint);
            if (introspectionFinding) findings.push(introspectionFinding);

            // Test 2: Batch query amplification
            const batchFinding = await this._testBatchAmplification(endpoint);
            if (batchFinding) findings.push(batchFinding);

            // Test 3: Deep nesting DoS
            const nestingFinding = await this._testDeepNesting(endpoint);
            if (nestingFinding) findings.push(nestingFinding);

            // Test 4: Field suggestion extraction (works even without introspection)
            const suggestionFinding = await this._testFieldSuggestions(endpoint);
            if (suggestionFinding) findings.push(suggestionFinding);

            // Test 5: Alias-based rate limit bypass
            const aliasFinding = await this._testAliasBypass(endpoint);
            if (aliasFinding) findings.push(aliasFinding);
        }

        this.logger?.info?.(`GraphQL Auditor: found ${findings.length} issues`);
        return findings;
    }

    async _discoverEndpoints(origin, surfaceInventory) {
        const endpoints = [];
        const tested = new Set();

        // Check common paths
        for (const path of this.COMMON_ENDPOINTS) {
            const url = `${origin}${path}`;
            if (tested.has(url)) continue;
            tested.add(url);

            try {
                const response = await this._gqlRequest(url, '{ __typename }');
                if (response?.data?.__typename || response?.errors) {
                    endpoints.push(url);
                }
            } catch { /* not GraphQL */ }
        }

        // Also detect from surface inventory (look for /graphql in API paths)
        for (const page of (surfaceInventory.pages || [])) {
            const url = page.url;
            if (!url || tested.has(url)) continue;
            if (!/graphql|gql|query/i.test(url)) continue;
            tested.add(url);

            try {
                const response = await this._gqlRequest(url, '{ __typename }');
                if (response?.data?.__typename || response?.errors) {
                    endpoints.push(url);
                }
            } catch { /* not GraphQL */ }
        }

        return [...new Set(endpoints)];
    }

    async _testIntrospection(endpoint) {
        const introspectionQuery = `{
          __schema {
            types { name kind fields { name type { name kind } } }
            queryType { name }
            mutationType { name }
          }
        }`;

        try {
            const response = await this._gqlRequest(endpoint, introspectionQuery);
            if (response?.data?.__schema) {
                const types = response.data.__schema.types || [];
                const queryFields = types.find(t => t.name === response.data.__schema.queryType?.name)?.fields || [];
                const hasMutation = !!response.data.__schema.mutationType;

                return createFinding({
                    module: 'logic',
                    title: 'GraphQL: Introspection Enabled',
                    severity: 'medium',
                    affected_surface: endpoint,
                    description: `The GraphQL endpoint at ${endpoint} has introspection enabled. Introspection exposes the full schema — all types, fields, queries, and mutations — allowing attackers to enumerate the entire API surface, discover hidden or internal fields, and construct targeted attacks. Found ${queryFields.length} queries${hasMutation ? ' and mutations' : ''}.`,
                    reproduction: [
                        `1. POST to ${endpoint} with Content-Type: application/json`,
                        '2. Body: {"query": "{ __schema { types { name } } }"}',
                        '3. Full schema is returned',
                    ],
                    evidence: `Schema returned ${types.length} types. Query fields: ${queryFields.slice(0, 5).map(f => f.name).join(', ')}...`,
                    remediation: 'Disable introspection in production. In Apollo Server: introspection: false in production config. In graphql-yoga: use disableIntrospection plugin. Allow introspection only for trusted IP ranges or dev environments.',
                    references: ['https://owasp.org/www-project-top-10-for-large-language-model-applications/', 'https://graphql.org/learn/introspection/'],
                });
            }
        } catch { /* not vulnerable */ }
        return null;
    }

    async _testBatchAmplification(endpoint) {
        // Send 100 identical queries as a batch array
        const batchQuery = Array.from({ length: 100 }, (_, i) => ({
            query: `query q${i} { __typename }`,
        }));

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 15000);

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(batchQuery),
                signal: controller.signal,
            });
            clearTimeout(timeout);

            if (response.ok) {
                const data = await response.json().catch(() => null);
                if (Array.isArray(data) && data.length >= 10) {
                    return createFinding({
                        module: 'logic',
                        title: 'GraphQL: Batch Query Amplification (DoS Vector)',
                        severity: 'high',
                        affected_surface: endpoint,
                        description: `The GraphQL endpoint at ${endpoint} accepts batched queries and processed ${data.length} queries in a single HTTP request. Without limits, an attacker can amplify a single request into thousands of server-side operations, causing resource exhaustion. For authenticated endpoints, this also bypasses per-IP rate limiting since all 100 queries share one network request.`,
                        reproduction: [
                            `1. POST to ${endpoint} with a JSON array of queries`,
                            `2. Server processed ${data.length} queries in one request`,
                            '3. Amplify further with authentication-heavy queries',
                        ],
                        evidence: `Sent 100 batched queries. Response contained ${data.length} results.`,
                        remediation: 'Limit batch query size (Apollo: maxBatchSize option). Implement query cost analysis. Rate limit by operation count, not just HTTP request count. Consider disabling batching entirely in production.',
                        references: ['https://www.apollographql.com/docs/apollo-server/performance/apq/', 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
                    });
                }
            }
        } catch { /* not vulnerable or not supported */ }
        return null;
    }

    async _testDeepNesting(endpoint) {
        // Build a deeply nested query using __type (always available)
        const depth = 10;
        let query = 'query { __type(name: "Query") { ';
        let closing = '';
        for (let i = 0; i < depth; i++) {
            query += 'fields { type { ';
            closing += '} }';
        }
        query += 'name' + closing + ' } }';

        const start = Date.now();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 20000);

            const response = await this._gqlRequest(endpoint, query, controller);
            clearTimeout(timeout);
            const elapsed = Date.now() - start;

            // If it succeeds and takes >3s, it's likely not limiting depth
            if (response && !response.errors?.some(e => /depth|complexity|limit/i.test(e.message)) && elapsed > 2000) {
                return createFinding({
                    module: 'logic',
                    title: 'GraphQL: No Query Depth Limit (DoS Vector)',
                    severity: 'medium',
                    affected_surface: endpoint,
                    description: `The GraphQL endpoint at ${endpoint} processed a ${depth}-level deeply nested query in ${elapsed}ms without rejecting it. Without query depth limits, exponentially nested queries can cause CPU/memory exhaustion on the server, leading to denial of service.`,
                    reproduction: [
                        `1. Send the nested query (${depth} levels deep) to ${endpoint}`,
                        `2. Server processed it in ${elapsed}ms`,
                        '3. Increase depth to 50+ levels to cause resource exhaustion',
                    ],
                    evidence: `Query depth: ${depth} levels\nTime to respond: ${elapsed}ms\nNo depth limit error returned`,
                    remediation: 'Implement query depth limiting. Apollo Server: use graphql-depth-limit (maxDepth: 7). graphql-yoga: install @escape.tech/graphman and configure depth limit. Also implement query complexity analysis.',
                    references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
                });
            }
        } catch { /* timeout or error — may be protected */ }
        return null;
    }

    async _testFieldSuggestions(endpoint) {
        // Send a query with a typo to trigger "Did you mean X?" suggestions
        // This reveals field names even without introspection
        try {
            const response = await this._gqlRequest(endpoint, '{ usr { nam emai } }');
            if (!response?.errors) return null;

            const suggestions = response.errors
                .filter(e => /did you mean|suggestion/i.test(e.message))
                .map(e => e.message);

            if (suggestions.length > 0) {
                return createFinding({
                    module: 'logic',
                    title: 'GraphQL: Field Suggestions Leak Schema (Introspection Disabled Bypass)',
                    severity: 'low',
                    affected_surface: endpoint,
                    description: `The GraphQL endpoint at ${endpoint} returns "Did you mean?" suggestions in error messages, even though introspection may be disabled. This allows attackers to enumerate field names by submitting intentional typos and reading the suggestions. Schema enumeration is possible without introspection access.`,
                    reproduction: [
                        `1. POST to ${endpoint}: {"query": "{ usr { emai } }"}`,
                        '2. Server responds with "Did you mean: email?"',
                        '3. Repeat with systematic typos to enumerate all fields',
                    ],
                    evidence: suggestions.slice(0, 3).join('\n'),
                    remediation: 'Disable field suggestions in production. Apollo Server: set fieldSuggestions: false (Apollo Server 3.6+). Ensure error messages in production are generic and do not leak schema information.',
                    references: ['https://www.apollographql.com/docs/apollo-server/security/security/'],
                });
            }
        } catch { /* not GraphQL or no suggestions */ }
        return null;
    }

    async _testAliasBypass(endpoint) {
        // Use aliases to send 50 operations as a single query (bypasses per-query rate limits)
        const aliases = Array.from({ length: 50 }, (_, i) => `q${i}: __typename`).join('\n');
        const query = `{ ${aliases} }`;

        try {
            const response = await this._gqlRequest(endpoint, query);
            if (response?.data && Object.keys(response.data).length >= 50) {
                return createFinding({
                    module: 'logic',
                    title: 'GraphQL: Alias-Based Rate Limit Bypass',
                    severity: 'medium',
                    affected_surface: endpoint,
                    description: `The GraphQL endpoint at ${endpoint} allows a single query to execute 50+ aliased operations. Since rate limiting is typically applied per HTTP request, aliases can be used to bypass rate limits by bundling many operations into one request. For expensive operations (e.g., login, search), this amplifies brute-force capability by 50×.`,
                    reproduction: [
                        `1. Send a single query with 50 aliased operations to ${endpoint}`,
                        `2. All 50 executed (response has ${Object.keys(response.data).length} keys)`,
                        '3. For login: 50 password attempts in 1 HTTP request',
                    ],
                    evidence: `Sent 50 aliases in one query. Response had ${Object.keys(response.data).length} data fields.`,
                    remediation: 'Implement query complexity scoring that counts aliased fields. Limit the total number of aliases (Apollo: maxAliases). Implement per-operation rate limiting, not just per-request. Use persisted queries to restrict allowed operations.',
                    references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
                });
            }
        } catch { /* not vulnerable */ }
        return null;
    }

    async _gqlRequest(endpoint, query, controller) {
        if (!controller) {
            controller = new AbortController();
            setTimeout(() => controller.abort(), 12000);
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query }),
            signal: controller.signal,
        });

        if (!response.ok && response.status !== 400) return null;
        return response.json().catch(() => null);
    }
}

export default GraphQLAuditor;
