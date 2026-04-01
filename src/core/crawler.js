import { BrowserManager } from './browser-manager.js';
import pLimit from 'p-limit';
import { createFinding } from '../utils/finding.js';

export class Crawler {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.visited = new Set();
        this.surfaces = [];
        this.apiEndpoints = [];
        this.forms = [];
        this.consoleErrors = [];
        this.failedRequests = [];
        this.maxPages = config.crawler?.max_pages || 50;
        this.maxDepth = config.crawler?.max_depth || 5;
        this.timeout = config.crawler?.timeout || 30000;

        // Fix 1 & 3: Concurrency + rate limiting
        this.concurrency = config.crawler?.concurrency || 5;
        this.delayMs = config.crawler?.delay_ms ?? 100; // 100ms default polite delay

        this.baseUrl = null;
        this._queue = [];
        this._limit = null;
    }

    /**
     * Main crawl entry point. Returns a SurfaceInventory.
     * @param {string} targetUrl - URL to crawl
     * @param {object} [authState] - Playwright storageState for authenticated crawling
     * @param {string[]} [seedLinks] - Additional URLs to crawl (e.g., from post-login page)
     */
    async crawl(targetUrl, authState = null, seedLinks = []) {
        this.baseUrl = new URL(targetUrl);

        // Fix 1: Create a concurrency limiter (default: 5 pages in parallel)
        this._limit = pLimit(this.concurrency);

        const browser = await BrowserManager.launch({ headless: true });

        const contextOptions = {
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        };

        if (authState) {
            contextOptions.storageState = authState;
        }

        const context = await browser.newContext(contextOptions);

        try {
            // Seed initial URL(s) and process the queue
            this._enqueue(targetUrl, 0);

            // Also enqueue seed links (authenticated pages discovered during login)
            for (const link of seedLinks) {
                if (this._isSameOrigin(link)) {
                    this._enqueue(link, 0);
                }
            }

            // Process the queue until empty or limits reached
            await this._processQueue(context);

            // Backup discovery: if crawl found very few pages, try sitemap.xml and robots.txt
            if (this.surfaces.length <= 2) {
                this.logger?.info?.('Few pages discovered — trying sitemap.xml and robots.txt as backup discovery');
                const backupLinks = await this._discoverBackupLinks(targetUrl);
                for (const link of backupLinks) {
                    if (!this.visited.has(this._normalizeUrl(link)) && this._isSameOrigin(link)) {
                        this._enqueue(link, 1);
                    }
                }
                await this._processQueue(context);
            }
        } finally {
            await browser.close();
        }

        const inventory = {
            baseUrl: targetUrl,
            pages: this.surfaces,
            apiEndpoints: this.apiEndpoints,
            forms: this.forms,
            totalPages: this.surfaces.length,
            totalApis: this.apiEndpoints.length,
            totalForms: this.forms.length,
            crawledAt: new Date().toISOString(),
            authenticated: !!authState,
        };

        this.logger?.info?.(`Crawl complete: ${inventory.totalPages} pages, ${inventory.totalApis} APIs, ${inventory.totalForms} forms${authState ? ' (authenticated)' : ''}`);
        return inventory;
    }

    /**
     * Add a URL to the crawl queue.
     */
    _enqueue(url, depth) {
        const normalized = this._normalizeUrl(url);
        if (this.visited.has(normalized)) return;
        if (!this._isSameOrigin(url)) return;
        if (depth > this.maxDepth) return;
        if (this.visited.size >= this.maxPages) return;

        // Mark as visited immediately to prevent duplicate queueing
        this.visited.add(normalized);
        this._queue.push({ url, depth });
    }

    /**
     * Drain the queue concurrently up to the concurrency limit.
     */
    async _processQueue(context) {
        while (this._queue.length > 0 && this.surfaces.length < this.maxPages) {
            const batch = this._queue.splice(0, this._queue.length);
            const tasks = batch
                .filter(() => this.surfaces.length < this.maxPages)
                .map(({ url, depth }) =>
                    this._limit(() => this._crawlPage(context, url, depth))
                );
            await Promise.allSettled(tasks);
        }
    }

    /**
     * Crawls a single page and enqueues discovered links.
     */
    async _crawlPage(context, url, depth) {
        // Fix 3: Polite delay between requests
        if (this.delayMs > 0) {
            await new Promise(r => setTimeout(r, this.delayMs));
        }

        const normalizedUrl = this._normalizeUrl(url);
        const page = await context.newPage();
        const pageData = {
            url: normalizedUrl,
            type: 'page',
            status: null,
            title: '',
            links: [],
            forms: [],
            consoleErrors: [],
            failedRequests: [],
            loadTime: 0,
        };

        // Monitor console and network
        const consoleMessages = [];
        const failedReqs = [];

        page.on('console', msg => {
            if (msg.type() === 'error') {
                consoleMessages.push({
                    type: msg.type(),
                    text: msg.text(),
                    url: normalizedUrl,
                });
            }
        });

        page.on('pageerror', error => {
            consoleMessages.push({
                type: 'exception',
                text: error.message,
                url: normalizedUrl,
            });
        });

        page.on('requestfailed', request => {
            failedReqs.push({
                url: request.url(),
                method: request.method(),
                failure: request.failure()?.errorText || 'Unknown',
                page: normalizedUrl,
            });
        });

        // Intercept API calls
        page.on('response', response => {
            const reqUrl = response.url();
            const contentType = response.headers()['content-type'] || '';

            // Fix 3: Respect Retry-After header
            const retryAfter = response.headers()['retry-after'];
            if (retryAfter && (response.status() === 429 || response.status() === 503)) {
                const waitMs = Math.min(parseInt(retryAfter, 10) * 1000 || 5000, 30000);
                this.logger?.warn?.(`Rate limited (${response.status()}) — backing off ${waitMs}ms`);
                // Increase delay temporarily
                this.delayMs = Math.max(this.delayMs, waitMs);
            }

            if (contentType.includes('application/json') && this._isSameOrigin(reqUrl)) {
                const existing = this.apiEndpoints.find(e => e.url === reqUrl && e.method === response.request().method());
                if (!existing) {
                    this.apiEndpoints.push({
                        url: reqUrl,
                        method: response.request().method(),
                        status: response.status(),
                        contentType,
                    });
                }
            }
        });

        try {
            const startTime = Date.now();

            // Progressive fallback: networkidle → load → domcontentloaded
            let response = null;
            const strategies = ['networkidle', 'load', 'domcontentloaded'];

            for (const strategy of strategies) {
                try {
                    const strategyTimeout = strategy === 'networkidle' ? this.timeout : Math.min(this.timeout, 15000);
                    response = await page.goto(url, {
                        waitUntil: strategy,
                        timeout: strategyTimeout,
                    });
                    this.logger?.debug?.(`Page loaded with '${strategy}' strategy: ${normalizedUrl}`);
                    break;
                } catch (navErr) {
                    if (strategy !== strategies[strategies.length - 1]) {
                        this.logger?.debug?.(`'${strategy}' timed out for ${normalizedUrl}, trying '${strategies[strategies.indexOf(strategy) + 1]}'`);
                    } else {
                        this.logger?.warn?.(`All load strategies failed for ${normalizedUrl}: ${navErr.message}`);
                    }
                }
            }

            pageData.loadTime = Date.now() - startTime;
            pageData.status = response?.status() || null;
            pageData.title = await page.title().catch(() => '');

            // Extract links
            const links = await page.evaluate(() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                return anchors.map(a => a.href).filter(href => href && !href.startsWith('javascript:'));
            }).catch(() => []);
            pageData.links = [...new Set(links)];

            // Extract forms
            const pageForms = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('form')).map((form, idx) => {
                    const fields = Array.from(form.querySelectorAll('input, select, textarea')).map(field => ({
                        tag: field.tagName.toLowerCase(),
                        type: field.type || field.tagName.toLowerCase(),
                        name: field.name || field.id || `field-${idx}`,
                        required: field.required,
                        placeholder: field.placeholder || '',
                        pattern: field.pattern || '',
                        minLength: field.minLength > 0 ? field.minLength : null,
                        maxLength: field.maxLength > 0 ? field.maxLength : null,
                    }));

                    return {
                        action: form.action || window.location.href,
                        method: (form.method || 'get').toUpperCase(),
                        id: form.id || `form-${idx}`,
                        fields,
                        hasSubmitButton: !!form.querySelector('button[type="submit"], input[type="submit"]'),
                    };
                });
            }).catch(() => []);

            for (const form of pageForms) {
                form.page = normalizedUrl;
                this.forms.push(form);
            }
            pageData.forms = pageForms;
            pageData.consoleErrors = consoleMessages;
            pageData.failedRequests = failedReqs;

            this.consoleErrors.push(...consoleMessages);
            this.failedRequests.push(...failedReqs);
            this.surfaces.push(pageData);

            this.logger?.debug?.(`Crawled: ${normalizedUrl} (${pageData.status}) - ${links.length} links, ${pageForms.length} forms`);

            // Enqueue discovered links (non-blocking — queue is processed above)
            if (depth < this.maxDepth) {
                for (const link of pageData.links) {
                    this._enqueue(link, depth + 1);
                }
            }
        } catch (err) {
            const partialLinks = await page.evaluate(() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                return anchors.map(a => a.href).filter(href => href && !href.startsWith('javascript:'));
            }).catch(() => []);

            pageData.status = 'error';
            pageData.error = err.message;
            pageData.links = [...new Set(partialLinks)];
            this.surfaces.push(pageData);
            this.logger?.warn?.(`Failed to crawl ${normalizedUrl}: ${err.message}${partialLinks.length > 0 ? ` (extracted ${partialLinks.length} partial links)` : ''}`);

            if (depth < this.maxDepth) {
                for (const link of partialLinks) {
                    if (this._isSameOrigin(link)) {
                        this._enqueue(link, depth + 1);
                    }
                }
            }
        } finally {
            await page.close();
        }
    }

    _normalizeUrl(url) {
        try {
            const u = new URL(url);
            u.hash = '';
            let normalized = u.toString();
            if (normalized.endsWith('/') && u.pathname !== '/') {
                normalized = normalized.slice(0, -1);
            }
            return normalized;
        } catch {
            return url;
        }
    }

    _isSameOrigin(url) {
        try {
            const u = new URL(url);
            return u.origin === this.baseUrl.origin;
        } catch {
            return false;
        }
    }

    /**
     * Backup link discovery via sitemap.xml and robots.txt.
     */
    async _discoverBackupLinks(targetUrl) {
        const discovered = new Set();
        await this._discoverFromSitemap(targetUrl, discovered);
        await this._discoverFromRobots(targetUrl, discovered);
        const newLinks = [...discovered].filter(link => !this.visited.has(this._normalizeUrl(link)));
        if (newLinks.length > 0) {
            this.logger?.info?.(`Backup discovery found ${newLinks.length} new URLs from sitemap/robots`);
        }
        return newLinks;
    }

    async _discoverFromSitemap(targetUrl, discovered) {
        const sitemapUrls = [
            new URL('/sitemap.xml', targetUrl).toString(),
            new URL('/sitemap_index.xml', targetUrl).toString(),
        ];

        for (const sitemapUrl of sitemapUrls) {
            try {
                const resp = await fetch(sitemapUrl, {
                    signal: AbortSignal.timeout(10000),
                    redirect: 'follow',
                });
                if (!resp.ok) continue;

                const contentType = resp.headers.get('content-type') || '';
                if (!contentType.includes('xml') && !contentType.includes('text')) continue;

                const body = await resp.text();
                const locMatches = body.matchAll(/<loc>\s*(https?:\/\/[^<]+)\s*<\/loc>/gi);
                for (const match of locMatches) {
                    const url = match[1].trim();
                    if (this._isSameOrigin(url)) {
                        discovered.add(url);
                    }
                    if (url.includes('sitemap') && url.endsWith('.xml')) {
                        await this._discoverFromSitemap(url, discovered);
                    }
                }

                this.logger?.debug?.(`Parsed sitemap: ${sitemapUrl} → ${discovered.size} URLs`);
            } catch {
                // Sitemap not available
            }
        }
    }

    async _discoverFromRobots(targetUrl, discovered) {
        try {
            const robotsUrl = new URL('/robots.txt', targetUrl).toString();
            const resp = await fetch(robotsUrl, {
                signal: AbortSignal.timeout(10000),
                redirect: 'follow',
            });
            if (!resp.ok) return;

            const body = await resp.text();
            const lines = body.split('\n');

            for (const line of lines) {
                const trimmed = line.trim();

                if (trimmed.toLowerCase().startsWith('sitemap:')) {
                    const sitemapUrl = trimmed.substring(8).trim();
                    if (sitemapUrl.startsWith('http')) {
                        await this._discoverFromSitemap(sitemapUrl, discovered);
                    }
                }

                if (trimmed.toLowerCase().startsWith('disallow:')) {
                    const path = trimmed.substring(9).trim();
                    if (path && path !== '/' && path !== '*' && !path.includes('*')) {
                        try {
                            const fullUrl = new URL(path, targetUrl).toString();
                            if (this._isSameOrigin(fullUrl)) {
                                discovered.add(fullUrl);
                            }
                        } catch {
                            // Invalid path
                        }
                    }
                }
            }

            this.logger?.debug?.(`Parsed robots.txt → ${discovered.size} URLs`);
        } catch {
            // robots.txt not available
        }
    }
}

export default Crawler;
