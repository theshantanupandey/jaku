import { chromium } from 'playwright';
import { createFinding } from '../utils/finding.js';

/**
 * PerformanceChecker — Measures Core Web Vitals per page and reports regressions.
 *
 * Metrics:
 * - LCP  (Largest Contentful Paint) — Good: <2.5s, Poor: >4s
 * - CLS  (Cumulative Layout Shift)  — Good: <0.1, Poor: >0.25
 * - TTFB (Time to First Byte)       — Good: <800ms, Poor: >1800ms
 * - FCP  (First Contentful Paint)   — Good: <1.8s, Poor: >3s
 * - TBT  (Total Blocking Time)      — Good: <200ms, Poor: >600ms
 */
export class PerformanceChecker {
    // Google Core Web Vitals thresholds (ms, except CLS which is score)
    static THRESHOLDS = {
        LCP: { good: 2500, poor: 4000 },
        FCP: { good: 1800, poor: 3000 },
        TTFB: { good: 800, poor: 1800 },
        TBT: { good: 200, poor: 600 },
        CLS: { good: 0.1, poor: 0.25 },
    };

    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }

    async check(surfaceInventory) {
        const findings = [];
        const pages = surfaceInventory.pages.filter(p => p.status < 400).slice(0, 15);

        if (pages.length === 0) return findings;

        const browser = await chromium.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox'],
        });

        try {
            for (const pageData of pages) {
                const metrics = await this._measurePage(browser, pageData.url);
                if (!metrics) continue;

                const issues = this._evaluateMetrics(metrics, pageData.url);
                findings.push(...issues);

                this.logger?.debug?.(`Performance: ${pageData.url} — LCP:${metrics.LCP}ms FCP:${metrics.FCP}ms TTFB:${metrics.TTFB}ms CLS:${metrics.CLS}`);
            }
        } finally {
            await browser.close();
        }

        this.logger?.info?.(`Performance Checker: found ${findings.length} issues`);
        return findings;
    }

    async _measurePage(browser, url) {
        const page = await browser.newPage({
            viewport: { width: 1440, height: 900 },
        });

        try {
            // Enable CDPSession for TBT/LCP metrics
            const client = await page.context().newCDPSession(page);
            await client.send('Performance.enable');

            const startTime = Date.now();
            await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });

            // Give page time to fully paint
            await page.waitForTimeout(2000);

            const metrics = await page.evaluate(() => {
                const perf = window.performance;
                const navEntry = perf.getEntriesByType('navigation')[0];
                const paintEntries = perf.getEntriesByType('paint');

                const fcp = paintEntries.find(e => e.name === 'first-contentful-paint')?.startTime || null;

                // LCP via PerformanceObserver (collected passively)
                let lcp = null;
                const lcpEntries = perf.getEntriesByType('largest-contentful-paint');
                if (lcpEntries.length > 0) {
                    lcp = lcpEntries[lcpEntries.length - 1].startTime;
                }

                // CLS via LayoutShift entries
                let cls = 0;
                let clsSessionValue = 0;
                let clsSessionStart = 0;
                let clsLastTimestamp = 0;
                const layoutShiftEntries = perf.getEntriesByType('layout-shift');
                for (const entry of layoutShiftEntries) {
                    if (!entry.hadRecentInput) {
                        if (entry.startTime - clsLastTimestamp > 5000 || entry.startTime - clsSessionStart > 1000) {
                            clsSessionValue = entry.value;
                            clsSessionStart = entry.startTime;
                        } else {
                            clsSessionValue += entry.value;
                        }
                        clsLastTimestamp = entry.startTime;
                        if (clsSessionValue > cls) cls = clsSessionValue;
                    }
                }

                // TBT via Long Tasks
                let tbt = 0;
                const longTasks = perf.getEntriesByType('longtask');
                for (const task of longTasks) {
                    if (task.duration > 50) tbt += task.duration - 50;
                }

                return {
                    TTFB: navEntry ? Math.round(navEntry.responseStart - navEntry.requestStart) : null,
                    FCP: fcp ? Math.round(fcp) : null,
                    LCP: lcp ? Math.round(lcp) : null,
                    CLS: Math.round(cls * 1000) / 1000,
                    TBT: Math.round(tbt),
                };
            });

            return metrics;
        } catch (err) {
            this.logger?.debug?.(`Performance measure failed for ${url}: ${err.message}`);
            return null;
        } finally {
            await page.close();
        }
    }

    _evaluateMetrics(metrics, url) {
        const findings = [];
        const thresholds = PerformanceChecker.THRESHOLDS;

        const checks = [
            { key: 'LCP', label: 'Largest Contentful Paint', unit: 'ms' },
            { key: 'FCP', label: 'First Contentful Paint', unit: 'ms' },
            { key: 'TTFB', label: 'Time to First Byte', unit: 'ms' },
            { key: 'TBT', label: 'Total Blocking Time', unit: 'ms' },
            { key: 'CLS', label: 'Cumulative Layout Shift', unit: '' },
        ];

        for (const { key, label, unit } of checks) {
            const value = metrics[key];
            if (value === null || value === undefined) continue;

            const { good, poor } = thresholds[key];
            if (value <= good) continue; // Passes — no finding

            const isPoor = value > poor;
            const severity = isPoor ? 'medium' : 'low';
            const rating = isPoor ? 'Poor' : 'Needs Improvement';
            const displayVal = unit === 'ms' ? `${value}${unit}` : String(value);
            const goodDisplay = unit === 'ms' ? `${good}${unit}` : String(good);
            const poorDisplay = unit === 'ms' ? `${poor}${unit}` : String(poor);

            findings.push(createFinding({
                module: 'qa',
                title: `Performance: ${label} ${rating} (${displayVal}) — ${new URL(url).pathname}`,
                severity,
                affected_surface: url,
                description: `The page at ${url} has a ${label} of ${displayVal}, which Google rates as "${rating}" (Good: <${goodDisplay}, Poor: >${poorDisplay}). ${this._getImpact(key, value)}`,
                reproduction: [
                    `1. Run Lighthouse on ${url}`,
                    `2. Check ${label} in the Performance panel`,
                    `3. Current value: ${displayVal}`,
                ],
                evidence: `${key}: ${displayVal} (Good: <${goodDisplay}, Poor: >${poorDisplay})\nFull metrics: ${JSON.stringify(metrics)}`,
                remediation: this._getRemediation(key),
                references: [
                    'https://web.dev/articles/vitals',
                    `https://web.dev/articles/${key.toLowerCase()}`,
                ],
            }));
        }

        return findings;
    }

    _getImpact(key, value) {
        const impacts = {
            LCP: 'Slow LCP typically indicates render-blocking resources, slow server response, or large unoptimized images. Google uses this as a Core Web Vital for search ranking.',
            FCP: 'A slow FCP suggests excessive render-blocking CSS or scripts that prevent any content from appearing. Users may abandon the page before it loads.',
            TTFB: 'A high TTFB indicates slow server processing, database queries, or CDN latency. Every other metric is blocked until the first byte arrives.',
            TBT: 'High TBT means the main thread is blocked by long JavaScript tasks, making the page unresponsive to user input. Correlated with poor INP scores.',
            CLS: 'A high CLS causes layout instability — content shifting after initial render. This degrades UX and is a Core Web Vital used in Google\'s search ranking.',
        };
        return impacts[key] || '';
    }

    _getRemediation(key) {
        const remediations = {
            LCP: 'Optimize LCP: use preload <link> for hero images, serve images in WebP/AVIF, reduce TTFB via edge caching, remove render-blocking CSS (inline critical CSS), use font-display: swap.',
            FCP: 'Optimize FCP: eliminate render-blocking resources, minimize CSS and JS bundle sizes, use resource hints (preconnect, preload), defer non-critical scripts.',
            TTFB: 'Optimize TTFB: use CDN edge caching, optimize database queries (add indexes, avoid N+1), implement server-side caching (Redis), reduce DNS lookup time.',
            TBT: 'Reduce TBT: split large JavaScript bundles via code splitting, defer or async non-critical scripts, move heavy computation to Web Workers, minimize third-party script impact.',
            CLS: 'Reduce CLS: always set explicit width/height on images and videos, use CSS aspect-ratio, avoid inserting content above existing content dynamically, use transform animations instead of layout-triggering properties.',
        };
        return remediations[key] || 'Follow Google\'s Core Web Vitals guidelines at web.dev/vitals.';
    }
}

export default PerformanceChecker;
