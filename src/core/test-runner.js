import { BrowserManager } from './browser-manager.js';
import { createFinding } from '../utils/finding.js';
import { CSRWaiter } from './csr-waiter.js';
import fs from 'fs';
import path from 'path';

/**
 * Test Runner — Executes generated test cases headlessly via Playwright.
 * Captures screenshots on failure, records pass/fail, and generates findings.
 */
export class TestRunner {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.results = [];
        this.findings = [];
        this._pendingFailures = []; // collected before grouping
        this.screenshotDir = path.join(config.output_dir || 'jaku-reports', 'screenshots');
    }

    /**
     * Execute all generated test cases.
     */
    async run(testCases) {
        if (!fs.existsSync(this.screenshotDir)) {
            fs.mkdirSync(this.screenshotDir, { recursive: true });
        }

        const browser = await BrowserManager.launch({ headless: true });
        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        let passed = 0;
        let failed = 0;
        let errors = 0;

        for (const testCase of testCases) {
            try {
                const result = await this._executeTest(context, testCase);
                this.results.push(result);

                if (result.status === 'pass') {
                    passed++;
                } else {
                    failed++;
                    this._collectFailure(result);
                }
            } catch (err) {
                errors++;
                const errorResult = {
                    testCase,
                    status: 'error',
                    error: err.message,
                    duration: 0,
                };
                this.results.push(errorResult);
                this._collectFailure(errorResult);
            }
        }

        await browser.close();

        // Emit grouped findings (one per root-cause pattern, not one per URL)
        this._emitGroupedFindings();

        const summary = { total: testCases.length, passed, failed, errors };
        this.logger?.info?.(`Tests complete: ${passed} passed, ${failed} failed, ${errors} errors`);
        return { results: this.results, findings: this.findings, summary };
    }

    /**
     * Execute a single test case.
     */
    async _executeTest(context, testCase) {
        const page = await context.newPage();
        const startTime = Date.now();
        const csrWaiter = new CSRWaiter(this.logger);
        let status = 'pass';
        let failureReason = '';

        // Use CSRWaiter's filtered console listener — suppresses Supabase auth
        // loading noise so it doesn't false-positive on smoke tests
        const consoleErrors = CSRWaiter.installConsoleFilter(page);

        page.on('pageerror', error => {
            // Also filter page-level errors through the noise filter
            if (CSRWaiter.isRealError(error.message)) {
                consoleErrors.push({ type: 'exception', text: error.message, timestamp: Date.now(), url: page.url() });
            }
        });

        try {
            for (let i = 0; i < testCase.steps.length; i++) {
                const step = testCase.steps[i];
                await this._executeStep(page, step, testCase);

                // After the first navigation step, wait for CSR content to settle
                // This is the key fix for Supabase/Clerk/CSR app false positives
                if (i === 0 && (step.action === 'navigate' || step.action === 'goto')) {
                    await csrWaiter.waitForContent(page, { timeout: 12000 });
                }
            }

            // Validate expected outcomes
            if (testCase.type === 'smoke') {
                const realErrorCount = consoleErrors.filter(e => e.type === 'error' || e.type === 'exception').length;
                if (realErrorCount > 0 && testCase.expected.noConsoleErrors) {
                    status = 'fail';
                    failureReason = `Console errors detected: ${consoleErrors.map(e => e.text).join('; ')}`;
                }
            }
        } catch (err) {
            status = 'fail';
            failureReason = err.message;

            // Capture screenshot on failure
            try {
                const screenshotPath = path.join(
                    this.screenshotDir,
                    `${testCase.id}-failure.png`
                );
                await page.screenshot({ path: screenshotPath, fullPage: true });
            } catch {
                // Screenshot capture is best-effort
            }
        }

        const duration = Date.now() - startTime;
        await page.close();

        return {
            testCase,
            status,
            failureReason,
            consoleErrors,
            duration,
        };
    }

    /**
     * Execute a single step of a test case.
     */
    async _executeStep(page, step, testCase) {
        switch (step.action) {
            case 'navigate':
                const response = await page.goto(step.url, {
                    waitUntil: 'networkidle',
                    timeout: 15000,
                });
                if (step.expected === undefined) break;
                break;

            case 'assert_status':
                const currentUrl = page.url();
                const resp = await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                if (resp) {
                    const expectedStatuses = Array.isArray(step.expected) ? step.expected : [step.expected];
                    if (!expectedStatuses.includes(resp.status())) {
                        throw new Error(`Expected HTTP ${step.expected}, got ${resp.status()}`);
                    }
                }
                break;

            case 'assert_no_console_errors':
                // Checked after all steps in _executeTest
                break;

            case 'assert_has_content':
                const bodyText = await page.evaluate(() => document.body?.innerText?.trim() || '');
                if (!bodyText) {
                    throw new Error('Page has no visible content (empty body)');
                }
                break;

            case 'click_link':
                try {
                    const linkSelector = `a[href="${step.url}"]`;
                    const link = await page.$(linkSelector);
                    if (link) {
                        await link.click({ timeout: 5000 });
                        await page.waitForLoadState('networkidle', { timeout: 10000 });
                    } else {
                        await page.goto(step.url, { waitUntil: 'networkidle', timeout: 10000 });
                    }
                } catch {
                    await page.goto(step.url, { waitUntil: 'networkidle', timeout: 10000 });
                }
                break;

            case 'locate_form':
                const form = await page.$(`form#${step.selector}`) || await page.$('form');
                if (!form) {
                    throw new Error(`Form "${step.selector}" not found on page`);
                }
                break;

            case 'submit_empty':
                const submitBtn = await page.$('button[type="submit"], input[type="submit"]');
                if (submitBtn) {
                    await submitBtn.click();
                    await page.waitForTimeout(1000);
                }
                break;

            case 'fill_form':
                if (step.data) {
                    for (const [name, value] of Object.entries(step.data)) {
                        try {
                            const input = await page.$(`[name="${name}"]`) || await page.$(`#${name}`);
                            if (input) {
                                if (typeof value === 'boolean') {
                                    if (value) await input.check();
                                } else if (value === '__first_option__') {
                                    await input.selectOption({ index: 1 });
                                } else {
                                    await input.fill(String(value));
                                }
                            }
                        } catch {
                            // Best-effort field fill
                        }
                    }
                }
                break;

            case 'fill_field':
                try {
                    const field = await page.$(`[name="${step.field}"]`) || await page.$(`#${step.field}`);
                    if (field) {
                        await field.fill(String(step.value));
                    }
                } catch {
                    // Best-effort field fill
                }
                break;

            case 'submit':
                const btn = await page.$('button[type="submit"], input[type="submit"]');
                if (btn) {
                    await btn.click();
                    await page.waitForTimeout(1000);
                }
                break;

            case 'assert_validation_error':
            case 'assert_submission_feedback':
            case 'assert_no_crash':
            case 'assert_input_sanitized':
            case 'assert_valid_json':
            case 'assert_response_time':
                // These are checked post-execution or are informational
                break;

            case 'http_request':
                try {
                    const fetchResp = await page.evaluate(async (opts) => {
                        const resp = await fetch(opts.url, { method: opts.method });
                        return { status: resp.status, ok: resp.ok };
                    }, step);
                    if (!fetchResp.ok && step.expected) {
                        const expected = Array.isArray(step.expected) ? step.expected : [step.expected];
                        if (!expected.includes(fetchResp.status)) {
                            throw new Error(`API returned ${fetchResp.status}`);
                        }
                    }
                } catch (err) {
                    throw new Error(`API request failed: ${err.message}`);
                }
                break;

            default:
                this.logger?.debug?.(`Unknown step action: ${step.action}`);
        }
    }

    /**
     * Collect a failure for later grouping (do not emit immediately).
     */
    _collectFailure(result) {
        this._pendingFailures.push(result);
    }

    /**
     * Group collected failures by (type + normalized root cause) and emit one finding per group.
     *
     * Example: 49 smoke failures with "Page has no visible content (empty body)" on /trips/:uuid
     * becomes ONE high finding with all 49 URLs listed in the description.
     */
    _emitGroupedFindings() {
        // Group key: type + root-cause message (first ~80 chars to normalize minor variance)
        const groups = new Map();

        for (const result of this._pendingFailures) {
            const { testCase, failureReason, error } = result;
            const message = (failureReason || error || 'Test failed').substring(0, 80);
            const key = `${testCase.type}::${message}`;

            if (!groups.has(key)) {
                groups.set(key, {
                    type: testCase.type,
                    message,
                    results: [],
                    firstTestCase: testCase,
                });
            }
            groups.get(key).results.push(result);
        }

        for (const [, group] of groups) {
            const { type, message, results, firstTestCase } = group;
            const count = results.length;
            const urls = results.map(r => r.testCase.surface).filter(Boolean);

            const severityMap = {
                'smoke': 'high',
                'navigation': 'medium',
                'form': 'medium',
                'api': 'high',
                'edge-case': 'low',
            };

            // For a group of 1, preserve the original specific title.
            // For groups of 2+, produce a single grouped finding.
            const title = count === 1
                ? `Test Failed: ${firstTestCase.title}`
                : `Test Failed (${count}x): ${message}`;

            const description = count === 1
                ? `Test "${firstTestCase.title}" (${type}) failed: ${message}`
                : `${count} pages share the same root cause: "${message}"\n\nAffected URLs:\n${urls.map(u => `  - ${u}`).join('\n')}`;

            this.findings.push(
                createFinding({
                    module: 'qa',
                    title,
                    severity: severityMap[type] || 'medium',
                    affected_surface: count === 1 ? firstTestCase.surface : urls[0],
                    description,
                    reproduction: count === 1
                        ? firstTestCase.steps.map((s, i) =>
                            `${i + 1}. ${s.action}${s.url ? ` → ${s.url}` : ''}${s.value ? ` with value "${String(s.value).substring(0, 50)}"` : ''}`
                        )
                        : [
                            `1. navigate → any of the ${count} affected URLs`,
                            `2. assert_status (expect 200)`,
                            `3. assert_has_content`,
                            `4. Fails with: ${message}`,
                        ],
                    evidence: JSON.stringify({
                        groupedCount: count,
                        rootCause: message,
                        testType: type,
                        affectedUrls: urls,
                        firstTestId: firstTestCase.id,
                    }, null, 2),
                    remediation: this._getRemediation(firstTestCase, message),
                })
            );
        }

        if (this._pendingFailures.length > 0) {
            this.logger?.info?.(`Test findings: ${this._pendingFailures.length} failures → ${this.findings.length} grouped findings`);
        }
    }

    /**
     * Create a finding from a failed test (legacy single-emit path — kept for direct calls).
     */
    _createFindingFromResult(result) {
        // Redirect to the grouping path
        this._collectFailure(result);
        this._emitGroupedFindings();
        this._pendingFailures = [];
    }

    _getRemediation(testCase, message) {
        switch (testCase.type) {
            case 'smoke':
                return 'Ensure the page loads correctly with HTTP 200, has visible content, and produces no JavaScript errors.';
            case 'navigation':
                return 'Fix the broken link or ensure the target URL is accessible. Update or remove any stale links.';
            case 'form':
                if (testCase.subtype === 'empty_submit') return 'Add proper form validation to prevent empty submissions.';
                if (testCase.subtype === 'invalid_input') return `Add input validation for field "${testCase.fieldName}" to reject invalid data.`;
                return 'Ensure form submission works correctly with proper validation and user feedback.';
            case 'api':
                return 'Verify the API endpoint is accessible, returns valid JSON, and responds within acceptable time limits.';
            case 'edge-case':
                return 'Ensure the application handles edge cases gracefully without crashing - long inputs, special characters, etc.';
            default:
                return 'Investigate and fix the test failure.';
        }
    }
}

export default TestRunner;
