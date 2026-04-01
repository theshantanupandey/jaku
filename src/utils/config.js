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
    },
    viewports: {
        mobile: { width: 375, height: 812 },
        tablet: { width: 768, height: 1024 },
        desktop: { width: 1440, height: 900 },
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

    // CLI overrides
    if (cliOptions.targetUrl) config.target_url = cliOptions.targetUrl;
    if (cliOptions.severity) config.severity_threshold = cliOptions.severity;
    if (cliOptions.output) config.output_dir = cliOptions.output;
    if (cliOptions.verbose !== undefined) config.verbose = cliOptions.verbose;
    if (cliOptions.json) config.output_json = true;
    if (cliOptions.html) config.output_html = true;

    return config;
}

export default loadConfig;
