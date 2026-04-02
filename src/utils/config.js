import fs from 'fs';
import path from 'path';

const DEFAULTS = {
    target_url: null,
    credentials: [],
    modules_enabled: ['qa'],
    severity_threshold: 'low',
    halt_on_critical: false,
    notify_webhook: null,
    crawler: {
        max_depth: 5,
        max_pages: 50,
        timeout: 30000,
        respect_robots_txt: true,
        concurrency: 4,
    },
    viewports: {
        mobile: { width: 375, height: 812 },
        tablet: { width: 768, height: 1024 },
        desktop: { width: 1440, height: 900 },
    },
};

/**
 * Scan Profile Presets
 *
 *   quick — Fast recon: fewer pages, shallow depth, best for development feedback loops
 *   deep  — Thorough: more pages, deep crawling, lower concurrency to avoid rate limits
 *   ci    — CI/CD optimized: moderate scope, fail-fast on critical findings
 */
const SCAN_PROFILES = {
    quick: {
        crawler: { max_pages: 10, max_depth: 2, concurrency: 4, timeout: 15000 },
        modules_enabled: ['qa', 'security'],
    },
    deep: {
        crawler: { max_pages: 200, max_depth: 10, concurrency: 2, timeout: 60000 },
        modules_enabled: ['qa', 'security', 'ai', 'logic', 'api'],
    },
    ci: {
        crawler: { max_pages: 30, max_depth: 3, concurrency: 4, timeout: 20000 },
        modules_enabled: ['qa', 'security', 'ai', 'logic', 'api'],
        halt_on_critical: true,
    },
};

export function loadConfig(cliOptions = {}) {
    let fileConfig = {};

    // Load from config file if specified or default path exists
    const configPath = cliOptions.config || path.join(process.cwd(), 'jaku.config.json');
    if (fs.existsSync(configPath)) {
        try {
            const raw = fs.readFileSync(configPath, 'utf-8');
            fileConfig = JSON.parse(raw);
        } catch (e) {
            console.warn(`⚠ Warning: Could not parse config file at ${configPath}`);
        }
    }

    // Merge: defaults < file config < CLI options
    const config = {
        ...DEFAULTS,
        ...fileConfig,
        crawler: { ...DEFAULTS.crawler, ...(fileConfig.crawler || {}) },
        viewports: { ...DEFAULTS.viewports, ...(fileConfig.viewports || {}) },
    };

    // Apply scan profile (overrides default settings)
    const profileName = cliOptions.profile;
    if (profileName && SCAN_PROFILES[profileName]) {
        const profile = SCAN_PROFILES[profileName];
        if (profile.crawler) {
            Object.assign(config.crawler, profile.crawler);
        }
        if (profile.modules_enabled) {
            config.modules_enabled = profile.modules_enabled;
        }
        if (profile.halt_on_critical !== undefined) {
            config.halt_on_critical = profile.halt_on_critical;
        }
        config._profile = profileName;
    }

    // CLI overrides (take priority over profiles)
    if (cliOptions.targetUrl) config.target_url = cliOptions.targetUrl;
    if (cliOptions.severity) config.severity_threshold = cliOptions.severity;
    if (cliOptions.output) config.output_dir = cliOptions.output;
    if (cliOptions.verbose !== undefined) config.verbose = cliOptions.verbose;
    if (cliOptions.json) config.output_json = true;
    if (cliOptions.html) config.output_html = true;
    if (cliOptions.maxPages) config.crawler.max_pages = parseInt(cliOptions.maxPages);
    if (cliOptions.maxDepth) config.crawler.max_depth = parseInt(cliOptions.maxDepth);

    return config;
}

export { SCAN_PROFILES };
export default loadConfig;

