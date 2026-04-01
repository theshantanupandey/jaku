import { BaseAgent } from './base-agent.js';
import { HeaderAnalyzer } from '../core/security/header-analyzer.js';
import { SecretDetector } from '../core/security/secret-detector.js';
import { XSSScanner } from '../core/security/xss-scanner.js';
import { SQLiProber } from '../core/security/sqli-prober.js';
import { DependencyAuditor } from '../core/security/dependency-auditor.js';
import { TLSChecker } from '../core/security/tls-checker.js';
import { InfraScanner } from '../core/security/infra-scanner.js';
import { FileUploadTester } from '../core/security/file-upload-tester.js';
import { CORSProber } from '../core/security/cors-prober.js';
import { CSRFProber } from '../core/security/csrf-prober.js';
import { PrototypePollutionScanner } from '../core/security/prototype-pollution.js';
import { PathTraversalScanner } from '../core/security/path-traversal.js';

/**
 * JAKU-SEC — Security Vulnerability Scanning Agent
 *
 * Pipeline (12 phases):
 * 1. Header Analysis      — CSP, HSTS, X-Frame-Options, etc.
 * 2. Secret Detection     — API keys, tokens, credentials in JS/HTML
 * 3. XSS Scanning         — Reflected, stored, DOM, AngularJS/Vue template injection
 * 4. SQL Injection         — Error-based, boolean-based, time-based
 * 5. Dependency Audit     — CVE lookup for npm/pip/gem packages
 * 6. TLS Check            — Protocol version, cipher strength, cert validity
 * 7. Infrastructure Scan  — Open ports, service disclosure, misconfigured services
 * 8. File Upload Testing  — MIME bypass, polyglot files, path traversal in upload
 * 9. CORS Probing         — Arbitrary origin reflection, null origin, pre-flight bypass
 * 10. CSRF Probing        — Cookie SameSite, token absence, state-changing GET
 * 11. Prototype Pollution — __proto__ and constructor.prototype injection via URL/JSON
 * 12. Path Traversal / LFI — ../ variants, encoding bypasses, cloud metadata SSRF
 *
 * Dependencies: JAKU-CRAWL
 */
export class SecurityAgent extends BaseAgent {
    get name() { return 'JAKU-SEC'; }
    get dependencies() { return ['JAKU-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — JAKU-CRAWL must run first');
        }

        const phases = [
            { name: 'headers', label: 'Analyzing security headers' },
            { name: 'secrets', label: 'Scanning for exposed secrets' },
            { name: 'xss', label: 'Probing for XSS vulnerabilities' },
            { name: 'sqli', label: 'Probing for SQL injection' },
            { name: 'deps', label: 'Auditing dependencies' },
            { name: 'tls', label: 'Checking TLS configuration' },
            { name: 'infra', label: 'Scanning infrastructure' },
            { name: 'upload', label: 'Testing file upload security' },
            { name: 'cors', label: 'Probing CORS misconfigurations' },
            { name: 'csrf', label: 'Testing CSRF protection' },
            { name: 'proto', label: 'Scanning for prototype pollution' },
            { name: 'traversal', label: 'Testing path traversal / LFI' },
        ];

        let completedPhases = 0;

        // Phase 1: Header Analysis
        this.progress(phases[0].name, phases[0].label, 0);
        try {
            const analyzer = new HeaderAnalyzer(logger);
            const findings = await analyzer.analyze(surfaceInventory);
            this.addFindings(findings);
            this._log(`Headers: ${findings.length} issues`);
        } catch (err) {
            this._log(`Header analysis failed: ${err.message}`, 'error');
        }
        completedPhases++;
        this.progress(phases[0].name, 'Header analysis complete', (completedPhases / phases.length) * 100);

        // Phase 2: Secret Detection
        this.progress(phases[1].name, phases[1].label, (completedPhases / phases.length) * 100);
        try {
            const detector = new SecretDetector(logger);
            const findings = await detector.detect(surfaceInventory);
            this.addFindings(findings);
            this._log(`Secrets: ${findings.length} exposures`);
        } catch (err) {
            this._log(`Secret detection failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 3: XSS Scanning
        this.progress(phases[2].name, phases[2].label, (completedPhases / phases.length) * 100);
        try {
            const scanner = new XSSScanner(logger);
            const findings = await scanner.scan(surfaceInventory);
            this.addFindings(findings);
            this._log(`XSS: ${findings.length} vulnerabilities`);
        } catch (err) {
            this._log(`XSS scanning failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 4: SQL Injection Probing
        this.progress(phases[3].name, phases[3].label, (completedPhases / phases.length) * 100);
        try {
            const prober = new SQLiProber(logger);
            const findings = await prober.probe(surfaceInventory);
            this.addFindings(findings);
            this._log(`SQLi: ${findings.length} vulnerabilities`);
        } catch (err) {
            this._log(`SQLi probing failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 5: Dependency Audit
        this.progress(phases[4].name, phases[4].label, (completedPhases / phases.length) * 100);
        try {
            const auditor = new DependencyAuditor(config, logger);
            const findings = await auditor.audit();
            this.addFindings(findings);
            this._log(`Dependencies: ${findings.length} issues`);
        } catch (err) {
            this._log(`Dependency audit failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 6: TLS/SSL Check
        this.progress(phases[5].name, phases[5].label, (completedPhases / phases.length) * 100);
        try {
            const checker = new TLSChecker(logger);
            const findings = await checker.check(surfaceInventory);
            this.addFindings(findings);
            this._log(`TLS: ${findings.length} issues`);
        } catch (err) {
            this._log(`TLS check failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 7: Infrastructure Scan
        this.progress(phases[6].name, phases[6].label, (completedPhases / phases.length) * 100);
        try {
            const scanner = new InfraScanner(logger);
            const findings = await scanner.scan(surfaceInventory);
            this.addFindings(findings);
            this._log(`Infrastructure: ${findings.length} issues`);
        } catch (err) {
            this._log(`Infrastructure scan failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 8: File Upload Testing
        this.progress(phases[7].name, phases[7].label, (completedPhases / phases.length) * 100);
        try {
            const uploader = new FileUploadTester(logger);
            const findings = await uploader.test(surfaceInventory);
            this.addFindings(findings);
            this._log(`File uploads: ${findings.length} issues`);
        } catch (err) {
            this._log(`File upload testing failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 9: CORS Probing
        this.progress(phases[8].name, phases[8].label, (completedPhases / phases.length) * 100);
        try {
            const corsProber = new CORSProber(logger);
            const findings = await corsProber.probe(surfaceInventory);
            this.addFindings(findings);
            this._log(`CORS: ${findings.length} misconfigurations`);
        } catch (err) {
            this._log(`CORS probing failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 10: CSRF Probing
        this.progress(phases[9].name, phases[9].label, (completedPhases / phases.length) * 100);
        try {
            const csrfProber = new CSRFProber(logger);
            const findings = await csrfProber.probe(surfaceInventory);
            this.addFindings(findings);
            this._log(`CSRF: ${findings.length} issues`);
        } catch (err) {
            this._log(`CSRF probing failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 11: Prototype Pollution
        this.progress(phases[10].name, phases[10].label, (completedPhases / phases.length) * 100);
        try {
            const ppScanner = new PrototypePollutionScanner(logger);
            const findings = await ppScanner.scan(surfaceInventory);
            this.addFindings(findings);
            this._log(`Prototype pollution: ${findings.length} issues`);
        } catch (err) {
            this._log(`Prototype pollution scan failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 12: Path Traversal / LFI
        this.progress(phases[11].name, phases[11].label, (completedPhases / phases.length) * 100);
        try {
            const traversalScanner = new PathTraversalScanner(logger);
            const findings = await traversalScanner.scan(surfaceInventory);
            this.addFindings(findings);
            this._log(`Path traversal: ${findings.length} issues`);
        } catch (err) {
            this._log(`Path traversal scan failed: ${err.message}`, 'error');
        }
        completedPhases++;

        this.progress('complete', `Security scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default SecurityAgent;
