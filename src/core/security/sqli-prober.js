import { chromium } from 'playwright';
import { createFinding } from '../../utils/finding.js';

/**
 * SQLi Prober — Tests query-bearing inputs for SQL/NoSQL injection vulnerabilities.
 * SAFETY: Simulation only — no destructive payloads (DROP, DELETE, etc.) are ever sent.
 */
export class SQLiProber {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
    }

    // SQL injection test payloads — detection-only, non-destructive
    static SQL_PAYLOADS = [
        { name: 'Single quote', payload: "'", errorPatterns: ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'odbc'] },
        { name: 'Classic OR', payload: "' OR '1'='1", errorPatterns: ['sql', 'syntax', 'query'] },
        { name: 'Double dash comment', payload: "' -- ", errorPatterns: ['sql', 'syntax'] },
        { name: 'UNION probe', payload: "' UNION SELECT NULL--", errorPatterns: ['union', 'select', 'column'] },
        { name: 'Boolean blind true', payload: "' AND '1'='1", errorPatterns: [] },
        { name: 'Boolean blind false', payload: "' AND '1'='2", errorPatterns: [] },
        { name: 'Numeric injection', payload: '1 OR 1=1', errorPatterns: ['sql', 'syntax'] },
        { name: 'Stacked query probe', payload: "'; SELECT 1--", errorPatterns: ['syntax', 'multiple'] },
    ];

    // NoSQL injection payloads for JSON bodies
    static NOSQL_PAYLOADS = [
        { name: 'NoSQL $gt operator', payload: { '$gt': '' }, desc: 'MongoDB greater-than operator' },
        { name: 'NoSQL $ne null', payload: { '$ne': null }, desc: 'MongoDB not-equal null' },
        { name: 'NoSQL $regex', payload: { '$regex': '.*' }, desc: 'MongoDB regex wildcard' },
    ];

    // Common SQL error signatures in responses
    static ERROR_SIGNATURES = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /PostgreSQL.*ERROR/i,
        /ERROR:\s*syntax error at or near/i,
        /pg_query\(\)/i,
        /Microsoft OLE DB Provider/i,
        /\[Microsoft\]\[ODBC/i,
        /ORA-\d{5}/i,
        /SQLite\/JDBCDriver/i,
        /SQLite\.Exception/i,
        /SQLITE_ERROR/i,
        /org\.hibernate\.QueryException/i,
        /Unclosed quotation mark/i,
        /quoted string not properly terminated/i,
        /com\.mysql\.jdbc/i,
        /Syntax error in string in query expression/i,
        /SQLSTATE\[\d{5}\]/i,
        /you have an error in your sql syntax/i,
    ];

    /**
     * Run SQL injection probing on all discovered surfaces.
     */
    async probe(surfaceInventory) {
        // Test URL parameters
        await this._testURLParams(surfaceInventory);

        // Test form inputs
        await this._testFormInputs(surfaceInventory);

        // Test API endpoints with JSON bodies
        await this._testAPIEndpoints(surfaceInventory);

        this.logger?.info?.(`SQLi prober found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Test URL query parameters for SQL injection.
     */
    async _testURLParams(inventory) {
        for (const page of inventory.pages) {
            if (typeof page.status !== 'number') continue;

            try {
                const parsedUrl = new URL(page.url);
                const params = [...parsedUrl.searchParams.keys()];
                if (params.length === 0) continue;

                for (const param of params) {
                    for (const { name, payload } of SQLiProber.SQL_PAYLOADS.slice(0, 4)) {
                        const testUrl = new URL(page.url);
                        testUrl.searchParams.set(param, payload);

                        try {
                            const resp = await fetch(testUrl.toString(), {
                                signal: AbortSignal.timeout(10000),
                                redirect: 'follow',
                            });
                            const body = await resp.text();

                            const errorMatch = this._detectSQLError(body);
                            if (errorMatch) {
                                this.findings.push(createFinding({
                                    module: 'security',
                                    title: `SQL Injection: ${param} parameter (${name})`,
                                    severity: 'critical',
                                    affected_surface: page.url,
                                    description: `The URL parameter "${param}" appears vulnerable to SQL injection. The "${name}" payload triggered a database error in the response, indicating unsanitized input is being passed directly to SQL queries.\n\nError signature: ${errorMatch}`,
                                    reproduction: [
                                        `1. Navigate to: ${testUrl.toString()}`,
                                        `2. Observe database error message in the response`,
                                        `3. Error signature: ${errorMatch}`,
                                    ],
                                    evidence: JSON.stringify({ param, payload: name, errorSignature: errorMatch, responseSnippet: body.substring(0, 300) }),
                                    remediation: 'Use parameterized queries (prepared statements) for all database operations. Never concatenate user input into SQL strings. Implement input validation and WAF rules.',
                                    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'CWE-89'],
                                }));
                                break; // One finding per param
                            }
                        } catch {
                            // Request failed
                        }
                    }
                }
            } catch {
                // URL parsing failed
            }
        }
    }

    /**
     * Test form inputs for SQL injection.
     */
    async _testFormInputs(inventory) {
        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ ignoreHTTPSErrors: true });

        for (const form of inventory.forms) {
            const page = await context.newPage();
            try {
                await page.goto(form.page, { waitUntil: 'networkidle', timeout: 15000 });

                for (const field of form.fields) {
                    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(field.type)) continue;

                    // Test with the single quote payload (most universal SQL diagnostic)
                    const testPayload = SQLiProber.SQL_PAYLOADS[0];

                    try {
                        const input = await page.$(`[name="${field.name}"]`) || await page.$(`#${field.name}`);
                        if (!input) continue;

                        await input.fill(testPayload.payload);

                        // Submit
                        const submitBtn = await page.$('button[type="submit"], input[type="submit"]');
                        if (submitBtn) {
                            // Intercept response
                            const [response] = await Promise.all([
                                page.waitForNavigation({ timeout: 10000 }).catch(() => null),
                                submitBtn.click(),
                            ]);

                            await page.waitForTimeout(1000);
                            const content = await page.content();

                            const errorMatch = this._detectSQLError(content);
                            if (errorMatch) {
                                this.findings.push(createFinding({
                                    module: 'security',
                                    title: `SQL Injection: Form Field "${field.name}" in ${form.id}`,
                                    severity: 'critical',
                                    affected_surface: form.page,
                                    description: `The form field "${field.name}" in form "${form.id}" appears vulnerable to SQL injection. A single quote payload triggered a database error, indicating raw input is passed to SQL queries.\n\nError: ${errorMatch}`,
                                    reproduction: [
                                        `1. Navigate to ${form.page}`,
                                        `2. Enter a single quote (') in the "${field.name}" field`,
                                        `3. Submit the form`,
                                        `4. Observe SQL error in the response`,
                                    ],
                                    evidence: JSON.stringify({ form: form.id, field: field.name, errorSignature: errorMatch }),
                                    remediation: 'Use parameterized queries. Never pass raw form input to SQL queries.',
                                    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'CWE-89'],
                                }));
                            }

                            // Go back for next field
                            await page.goto(form.page, { waitUntil: 'networkidle', timeout: 10000 });
                        }
                    } catch {
                        // Field test failed
                    }
                }
            } catch (err) {
                this.logger?.debug?.(`SQLi form test failed for ${form.page}: ${err.message}`);
            } finally {
                await page.close();
            }
        }

        await browser.close();
    }

    /**
     * Test API endpoints for NoSQL injection via JSON bodies.
     */
    async _testAPIEndpoints(inventory) {
        for (const endpoint of inventory.apiEndpoints || []) {
            if (endpoint.method !== 'POST' && endpoint.method !== 'PUT') continue;

            for (const { name, payload, desc } of SQLiProber.NOSQL_PAYLOADS) {
                try {
                    // Send a JSON body with NoSQL operator
                    const resp = await fetch(endpoint.url, {
                        method: endpoint.method,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: payload, password: payload }),
                        signal: AbortSignal.timeout(10000),
                    });

                    const body = await resp.text();

                    // Check for unexpected success (auth bypass) or detailed errors
                    if (resp.ok && body.includes('token')) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `NoSQL Injection: ${name} at ${new URL(endpoint.url).pathname}`,
                            severity: 'critical',
                            affected_surface: endpoint.url,
                            description: `The API endpoint may be vulnerable to NoSQL injection. A ${desc} payload in the JSON body returned what appears to be a successful authentication response, suggesting the database query was manipulated.`,
                            reproduction: [
                                `1. Send ${endpoint.method} to ${endpoint.url}`,
                                `2. Body: ${JSON.stringify({ username: payload, password: payload })}`,
                                `3. Response contains authentication token`,
                            ],
                            evidence: JSON.stringify({ endpoint: endpoint.url, method: endpoint.method, payload: name }),
                            remediation: 'Validate and sanitize all input before database queries. Use explicit type checking to reject objects where strings are expected. Use mongoose schema validation or equivalent.',
                            references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
                        }));
                        break;
                    }
                } catch {
                    // Request failed
                }
            }
        }
    }

    /**
     * Check response body for SQL error signatures.
     */
    _detectSQLError(body) {
        if (!body) return null;
        for (const pattern of SQLiProber.ERROR_SIGNATURES) {
            const match = body.match(pattern);
            if (match) return match[0];
        }
        return null;
    }
}

export default SQLiProber;
