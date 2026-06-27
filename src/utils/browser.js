import fs from 'fs';
import { spawnSync } from 'node:child_process';
import { chromium } from 'playwright';

/**
 * Returns the path to the Chromium build Playwright expects, or null if it
 * cannot be resolved.
 */
function resolveChromiumPath() {
    try {
        const p = chromium.executablePath();
        return p || null;
    } catch {
        return null;
    }
}

/** True if the Chromium build is actually present on disk. */
export function isChromiumInstalled() {
    const p = resolveChromiumPath();
    return Boolean(p && fs.existsSync(p));
}

/**
 * Ensure Chromium is available before a scan. If it is missing, attempt a
 * one-time install (unless skipping is requested), then re-check.
 *
 * Throws a friendly Error if Chromium is required but unavailable so the CLI
 * can print actionable guidance instead of a raw Playwright stack trace.
 */
export function ensureChromium(logger) {
    if (isChromiumInstalled()) return true;

    const skip =
        process.env.JAKU_SKIP_BROWSER_DOWNLOAD ||
        process.env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD;
    if (skip) {
        throw new Error(
            'Chromium is not installed and a skip flag is set. Run: npx playwright install chromium'
        );
    }

    const msg = 'Chromium not found — installing it now (one-time, ~170 MB). This may take a minute...';
    logger?.info?.(msg);
    console.log(`  ${msg}`);

    try {
        spawnSync('npx', ['playwright', 'install', 'chromium'], {
            stdio: 'inherit',
            shell: process.platform === 'win32',
        });
    } catch {
        // fall through to the re-check below
    }

    if (!isChromiumInstalled()) {
        throw new Error(
            'Chromium is required but could not be installed automatically. Run: npx playwright install chromium'
        );
    }
    return true;
}
