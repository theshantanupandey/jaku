#!/usr/bin/env node
/**
 * JAKU postinstall — installs the Chromium build Playwright needs.
 *
 * Design goals (it must NEVER break `npm install`):
 *   - Skippable via JAKU_SKIP_BROWSER_DOWNLOAD / PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD.
 *   - Non-fatal: any failure (network, missing npx, etc.) exits 0 with guidance.
 *   - Interrupt-safe: a Ctrl+C (SIGINT) during the ~170 MB download leaves the
 *     CLI installed and exits 0 instead of failing the whole install. JAKU will
 *     auto-install the browser on first scan if it is still missing.
 */
import { spawnSync } from 'node:child_process';

function log(msg) {
    process.stdout.write(`${msg}\n`);
}

const MANUAL = 'Run `npx playwright install chromium` before your first scan.';

// If interrupted directly, don't fail the install.
process.on('SIGINT', () => {
    log(`\n⚠ JAKU: Chromium download interrupted. JAKU is installed — ${MANUAL}`);
    process.exit(0);
});

function main() {
    const skip =
        process.env.JAKU_SKIP_BROWSER_DOWNLOAD ||
        process.env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD;

    if (skip) {
        log(`JAKU: Skipping Chromium download (skip flag set). ${MANUAL}`);
        return 0;
    }

    log('JAKU: Installing Chromium for Playwright (~170 MB, one-time).');
    log('      Set JAKU_SKIP_BROWSER_DOWNLOAD=1 to skip; JAKU also auto-installs it on first scan.');

    let res;
    try {
        res = spawnSync('npx', ['playwright', 'install', 'chromium'], {
            stdio: 'inherit',
            shell: process.platform === 'win32',
        });
    } catch (e) {
        log(`⚠ JAKU: Could not auto-install Chromium (${e.message}). ${MANUAL}`);
        return 0;
    }

    if (res.signal) {
        log(`\n⚠ JAKU: Chromium install was interrupted (${res.signal}). JAKU is installed — ${MANUAL}`);
        return 0;
    }
    if (res.error) {
        log(`⚠ JAKU: Could not auto-install Chromium (${res.error.message}). ${MANUAL}`);
        return 0;
    }
    if (res.status !== 0) {
        log(`⚠ JAKU: Could not auto-install Chromium. ${MANUAL}`);
        return 0;
    }

    log('JAKU: Chromium ready. ✔');
    return 0;
}

// Always exit 0 — installing the CLI must never fail because of the browser.
try {
    process.exit(main());
} catch (e) {
    log(`⚠ JAKU: postinstall encountered an issue (${e.message}). ${MANUAL}`);
    process.exit(0);
}
