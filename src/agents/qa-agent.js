import { BaseAgent } from './base-agent.js';
import { BrokenFlowDetector } from '../core/broken-flow-detector.js';
import { ConsoleMonitor } from '../core/console-monitor.js';
import { TestGenerator } from '../core/test-generator.js';
import { TestRunner } from '../core/test-runner.js';
import { FormValidator } from '../core/form-validator.js';
import { ResponsiveChecker } from '../core/responsive-checker.js';
import { PerformanceChecker } from '../core/performance-checker.js';
import { AccessibilityChecker } from '../core/accessibility-checker.js';

/**
 * JAKU-QA — Quality Assurance & Functional Testing Agent
 *
 * Pipeline (7 phases):
 * 1. Broken Flow Detection  — 404s, redirect loops, missing auth redirects
 * 2. Console Monitoring     — JS errors, unhandled promises, network failures
 * 3. Test Generation & Run  — Smoke tests per discovered page with deduplication
 * 4. Form Validation        — Required fields, type checking, error messaging
 * 5. Responsive Checking    — Mobile/tablet/desktop layout issues
 * 6. Performance Checking   — Core Web Vitals: LCP, FCP, TTFB, TBT, CLS
 * 7. Accessibility Checking — WCAG 2.2 via axe-core (real-browser injection)
 *
 * Dependencies: JAKU-CRAWL
 */
export class QAAgent extends BaseAgent {
    get name() { return 'JAKU-QA'; }
    get dependencies() { return ['JAKU-CRAWL']; }

    constructor() {
        super();
        this._testSummary = {};
    }

    get testSummary() { return this._testSummary; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — JAKU-CRAWL must run first');
        }

        const phases = [
            { name: 'broken-flows', label: 'Detecting broken flows' },
            { name: 'console', label: 'Analyzing console output' },
            { name: 'tests', label: 'Generating & running tests' },
            { name: 'forms', label: 'Validating forms' },
            { name: 'responsive', label: 'Checking responsiveness' },
            { name: 'performance', label: 'Measuring Core Web Vitals' },
            { name: 'accessibility', label: 'Checking WCAG 2.2 accessibility' },
        ];

        let completedPhases = 0;

        // Phase 1: Broken Flow Detection
        this.progress(phases[0].name, phases[0].label, 0);
        try {
            const detector = new BrokenFlowDetector(logger);
            const findings = detector.analyze(surfaceInventory);
            this.addFindings(findings);
            this._log(`Broken flows: ${findings.length} issues`);
        } catch (err) {
            this._log(`Broken flow detection failed: ${err.message}`, 'error');
        }
        completedPhases++;
        this.progress(phases[0].name, `Broken flows complete`, (completedPhases / phases.length) * 100);

        // Phase 2: Console Monitoring
        this.progress(phases[1].name, phases[1].label, (completedPhases / phases.length) * 100);
        try {
            const monitor = new ConsoleMonitor(logger);
            const findings = monitor.analyze(surfaceInventory);
            this.addFindings(findings);
            this._log(`Console: ${findings.length} issues`);
        } catch (err) {
            this._log(`Console analysis failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 3: Test Generation & Execution
        this.progress(phases[2].name, phases[2].label, (completedPhases / phases.length) * 100);
        try {
            const generator = new TestGenerator(logger);
            const testCases = generator.generate(surfaceInventory);
            this._log(`Generated ${testCases.length} test cases`);

            const runner = new TestRunner(config, logger);
            const results = await runner.run(testCases);
            this._testSummary = results.summary;
            this.addFindings(results.findings);
            this._log(`Tests: ${results.summary.passed} passed, ${results.summary.failed} failed`);
        } catch (err) {
            this._log(`Test execution failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 4: Form Validation
        this.progress(phases[3].name, phases[3].label, (completedPhases / phases.length) * 100);
        try {
            const validator = new FormValidator(config, logger);
            const findings = await validator.validate(surfaceInventory);
            this.addFindings(findings);
            this._log(`Forms: ${findings.length} issues`);
        } catch (err) {
            this._log(`Form validation failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 5: Responsive Checking
        this.progress(phases[4].name, phases[4].label, (completedPhases / phases.length) * 100);
        try {
            const checker = new ResponsiveChecker(config, logger);
            const findings = await checker.check(surfaceInventory);
            this.addFindings(findings);
            this._log(`Responsive: ${findings.length} issues`);
        } catch (err) {
            this._log(`Responsive check failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 6: Performance Checking — Core Web Vitals
        this.progress(phases[5].name, phases[5].label, (completedPhases / phases.length) * 100);
        try {
            const perfChecker = new PerformanceChecker(config, logger);
            const findings = await perfChecker.check(surfaceInventory);
            this.addFindings(findings);
            this._log(`Performance: ${findings.length} issues`);
        } catch (err) {
            this._log(`Performance checking failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 7: Accessibility Checking — WCAG 2.2 / axe-core
        this.progress(phases[6].name, phases[6].label, (completedPhases / phases.length) * 100);
        try {
            const a11yChecker = new AccessibilityChecker(config, logger);
            const findings = await a11yChecker.check(surfaceInventory);
            this.addFindings(findings);
            this._log(`Accessibility: ${findings.length} issues`);
        } catch (err) {
            this._log(`Accessibility checking failed: ${err.message}`, 'error');
        }
        completedPhases++;

        this.progress('complete', `QA complete — ${this._findings.length} total findings`, 100);
    }
}

export default QAAgent;
