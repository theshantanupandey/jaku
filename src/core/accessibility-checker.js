import { chromium } from 'playwright';
import { createFinding } from '../utils/finding.js';

/**
 * AccessibilityChecker — Checks WCAG 2.2 compliance using axe-core.
 *
 * Categories:
 * - Critical: keyboard trap, missing form labels, missing alt text on interactive elements
 * - Serious: color contrast, focus visible, duplicate IDs
 * - Moderate: language attribute, skip navigation, heading order
 *
 * Uses axe-core injected via Playwright for accurate real-browser analysis.
 */
export class AccessibilityChecker {
    // axe-core CDN version to inject
    static AXE_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js';

    // Severity mapping from axe-core impact levels
    static SEVERITY_MAP = {
        critical: 'critical',
        serious: 'high',
        moderate: 'medium',
        minor: 'low',
    };

    // Categories to report (filter noise)
    static INCLUDE_RULES = new Set([
        'image-alt', 'label', 'label-content-name-mismatch', 'input-button-name',
        'button-name', 'link-name', 'aria-required-attr', 'aria-valid-attr',
        'color-contrast', 'color-contrast-enhanced',
        'keyboard', 'focus-trap', 'focusable-disabled', 'focus-order-semantics',
        'duplicate-id', 'duplicate-id-active', 'duplicate-id-aria',
        'html-has-lang', 'html-lang-valid', 'document-title',
        'heading-order', 'bypass', 'landmark-one-main',
        'form-field-multiple-labels', 'autocomplete-valid',
        'scrollable-region-focusable', 'select-name', 'textarea-label',
    ]);

    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }

    async check(surfaceInventory) {
        const findings = [];
        const pages = surfaceInventory.pages.filter(p => p.status < 400).slice(0, 15);

        if (pages.length === 0) return findings;

        const browser = await chromium.launch({ headless: true });

        try {
            for (const pageData of pages) {
                const results = await this._runAxe(browser, pageData.url);
                if (!results) continue;

                for (const violation of results) {
                    // Skip rules not in our inclusion list (reduces noise)
                    if (!AccessibilityChecker.INCLUDE_RULES.has(violation.id)) continue;

                    const severity = AccessibilityChecker.SEVERITY_MAP[violation.impact] || 'low';
                    const affectedCount = violation.nodes?.length || 1;

                    findings.push(createFinding({
                        module: 'qa',
                        title: `Accessibility (WCAG 2.2): ${violation.help} on ${new URL(pageData.url).pathname}`,
                        severity,
                        affected_surface: pageData.url,
                        description: `${violation.description} This violates WCAG 2.2 success criterion ${violation.helpUrl ? `(see reference)` : violation.id}. ${affectedCount} element${affectedCount > 1 ? 's are' : ' is'} affected on this page.\n\n${violation.help}.`,
                        reproduction: [
                            `1. Open ${pageData.url}`,
                            '2. Run axe-core in DevTools: await axe.run()',
                            `3. Look for violation: "${violation.id}"`,
                            `4. Affected selectors: ${(violation.nodes || []).slice(0, 3).map(n => n.target?.[0] || 'unknown').join(', ')}`,
                        ],
                        evidence: JSON.stringify({
                            rule: violation.id,
                            impact: violation.impact,
                            affectedCount,
                            sampleNodes: (violation.nodes || []).slice(0, 2).map(n => ({
                                target: n.target,
                                html: n.html?.substring(0, 150),
                                failureSummary: n.failureSummary,
                            })),
                        }, null, 2).substring(0, 800),
                        remediation: violation.helpUrl
                            ? `See axe-core guidance: ${violation.helpUrl}`
                            : this._getGenericRemediation(violation.id),
                        references: [
                            'https://www.w3.org/WAI/WCAG22/quickref/',
                            violation.helpUrl || 'https://dequeuniversity.com/rules/axe/',
                        ],
                    }));
                }

                this.logger?.debug?.(`Accessibility: ${pageData.url} — ${results.length} violations`);
            }
        } finally {
            await browser.close();
        }

        this.logger?.info?.(`Accessibility Checker: found ${findings.length} issues`);
        return findings;
    }

    async _runAxe(browser, url) {
        const page = await browser.newPage({
            viewport: { width: 1440, height: 900 },
        });

        try {
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
            await page.waitForTimeout(1500);

            // Inject axe-core
            await page.addScriptTag({ url: AccessibilityChecker.AXE_CDN }).catch(async () => {
                // Fallback: try local CDN or skip
                const axeSource = await this._fetchAxeCore().catch(() => null);
                if (axeSource) await page.addScriptTag({ content: axeSource });
            });

            await page.waitForTimeout(500);

            // Run axe
            const results = await page.evaluate(async () => {
                if (typeof axe === 'undefined') return null;
                const result = await axe.run(document, {
                    runOnly: {
                        type: 'tag',
                        values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'],
                    },
                });
                return result.violations;
            });

            return results;
        } catch (err) {
            this.logger?.debug?.(`Axe run failed for ${url}: ${err.message}`);
            return null;
        } finally {
            await page.close();
        }
    }

    async _fetchAxeCore() {
        try {
            const res = await fetch(AccessibilityChecker.AXE_CDN);
            return await res.text();
        } catch {
            return null;
        }
    }

    _getGenericRemediation(ruleId) {
        const remediations = {
            'image-alt': 'Add descriptive alt attributes to all <img> elements. Use alt="" for decorative images.',
            'label': 'Associate every form input with a visible <label> element using for/id pairing or aria-label.',
            'color-contrast': 'Ensure text has a contrast ratio of at least 4.5:1 (3:1 for large text) against its background. Use a contrast checker tool.',
            'keyboard': 'All interactive elements must be operable via keyboard alone. Test Tab, Enter, Space, Arrow keys.',
            'focus-trap': 'Never trap keyboard focus permanently in a component. Modal dialogs should trap focus but provide an escape path (Escape key, close button).',
            'duplicate-id': 'Each id attribute must be unique within the document. Duplicate IDs break ARIA relationships and cause accessibility failures.',
            'html-has-lang': 'Add a lang attribute to the <html> element to identify the page language (e.g., <html lang="en">).',
            'document-title': 'Every page must have a descriptive, unique <title> element.',
            'heading-order': 'Heading levels must not be skipped (e.g., h1 → h3 without h2). Maintain proper hierarchy.',
            'bypass': 'Provide a "Skip to main content" link as the first focusable element to allow keyboard users to bypass navigation.',
        };
        return remediations[ruleId] || 'Follow the WCAG 2.2 guidelines at https://www.w3.org/WAI/WCAG22/quickref/';
    }
}

export default AccessibilityChecker;
