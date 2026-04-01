import { chromium } from 'playwright';

/**
 * BrowserManager — Global Playwright browser lifecycle manager.
 *
 * Fixes:
 *  - Fix 2: Ensures browsers are always closed on process exit, even if agents
 *    crash mid-execution, preventing zombie Chromium processes on CI runners.
 *
 * Usage:
 *   const browser = await BrowserManager.launch({ headless: true });
 *   // browser is tracked globally and closed on process.exit
 */
export class BrowserManager {
    static _instances = new Set();
    static _exitHandlerRegistered = false;

    /**
     * Launch a new browser, registering it for automatic cleanup on exit.
     */
    static async launch(options = {}) {
        if (!BrowserManager._exitHandlerRegistered) {
            BrowserManager._registerExitHandlers();
        }

        const browser = await chromium.launch({ headless: true, ...options });
        BrowserManager._instances.add(browser);

        // Remove from registry when browser closes normally
        browser.on('disconnected', () => {
            BrowserManager._instances.delete(browser);
        });

        return browser;
    }

    /**
     * Wrap a function that uses a browser. Guarantees cleanup.
     * @param {object} options - Playwright launch options
     * @param {Function} fn - async (browser) => result
     */
    static async withBrowser(options, fn) {
        const browser = await BrowserManager.launch(options);
        try {
            return await fn(browser);
        } finally {
            await BrowserManager._closeSafely(browser);
        }
    }

    /**
     * Close all tracked browsers — called automatically on process exit.
     */
    static async closeAll() {
        const closePromises = [...BrowserManager._instances].map(b =>
            BrowserManager._closeSafely(b)
        );
        await Promise.allSettled(closePromises);
        BrowserManager._instances.clear();
    }

    static async _closeSafely(browser) {
        try {
            if (browser.isConnected()) {
                await browser.close();
            }
        } catch {
            // Best effort
        } finally {
            BrowserManager._instances.delete(browser);
        }
    }

    /**
     * Register exit handlers to clean up zombie browsers.
     */
    static _registerExitHandlers() {
        BrowserManager._exitHandlerRegistered = true;

        const cleanup = async (signal) => {
            if (BrowserManager._instances.size > 0) {
                await BrowserManager.closeAll();
            }
            // Re-emit after cleanup so the process actually exits
            if (signal) process.kill(process.pid, signal);
        };

        // Synchronous exit — use sync-compatible cleanup
        process.on('exit', () => {
            // Can't await in 'exit' handler — fire and forget
            for (const browser of BrowserManager._instances) {
                try { browser.close(); } catch { /* ignore */ }
            }
        });

        // Async-capable signals
        process.once('SIGINT', async () => {
            await cleanup('SIGINT');
        });

        process.once('SIGTERM', async () => {
            await cleanup('SIGTERM');
        });

        process.on('uncaughtException', async (err) => {
            console.error('[JAKU] Uncaught exception — cleaning up browsers:', err.message);
            await BrowserManager.closeAll();
            process.exit(1);
        });

        process.on('unhandledRejection', async (reason) => {
            console.error('[JAKU] Unhandled rejection — cleaning up browsers:', reason);
            await BrowserManager.closeAll();
            process.exit(1);
        });
    }
}

export default BrowserManager;
