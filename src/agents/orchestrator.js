import { EventBus } from './event-bus.js';
import { FindingsLedger } from './findings-ledger.js';

/**
 * Orchestrator — Central coordinator for the JAKU multi-agent system.
 * 
 * Responsibilities:
 * 1. Register and manage agent lifecycle
 * 2. Resolve dependencies via topological sort
 * 3. Execute independent agents in parallel
 * 4. Provide shared context (config, logger, event bus, surface inventory)
 * 5. Synthesize final results (dedup, correlate, score)
 */
export class Orchestrator {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.eventBus = new EventBus();
        this.ledger = new FindingsLedger(this.eventBus);

        this._agents = new Map();       // name → agent instance
        this._sharedContext = {         // passed to all agents
            config,
            logger,
            eventBus: this.eventBus,
            ledger: this.ledger,
            surfaceInventory: null,       // set by JAKU-CRAWL
        };

        this._startTime = null;
        this._haltedOnCritical = false;
    }

    /**
     * Register an agent with the orchestrator.
     */
    register(agent) {
        if (this._agents.has(agent.name)) {
            this.logger?.warn?.(`Agent "${agent.name}" already registered, skipping`);
            return this;
        }
        this._agents.set(agent.name, agent);
        this.logger?.info?.(`Registered agent: ${agent.name}`);
        return this; // chainable
    }

    /**
     * Subscribe to orchestrator events.
     */
    on(event, handler) {
        this.eventBus.on(event, handler);
        return this;
    }

    /**
     * Run all registered agents with dependency resolution and parallel execution.
     */
    async run() {
        this._startTime = Date.now();
        const executionOrder = this._resolveExecutionOrder();

        this.eventBus.emit('scan:started', {
            timestamp: new Date().toISOString(),
            modules: [...this._agents.keys()],
        });

        this.logger?.info?.(`Orchestrator starting with ${this._agents.size} agents`);
        this.logger?.info?.(`Execution order: ${executionOrder.map(g => g.map(a => a.name).join(' + ')).join(' → ')}`);

        // Initialize all agents
        for (const [, agent] of this._agents) {
            await agent.init(this._sharedContext);
        }

        // Listen for critical findings if halt_on_critical is enabled
        if (this.config.halt_on_critical) {
            this.eventBus.on('finding:new', ({ finding }) => {
                if (finding?.severity === 'critical') {
                    this._haltedOnCritical = true;
                    this.logger?.warn?.(`\n⛔ CRITICAL finding detected — halting scan (halt_on_critical=true)`);
                    this.logger?.warn?.(`   ${finding.title}`);
                }
            });
        }

        // Execute in dependency-resolved waves
        for (const wave of executionOrder) {
            if (wave.length === 1) {
                // Single agent — run sequentially
                await this._runAgent(wave[0]);
            } else {
                // Multiple agents — run in parallel
                this.logger?.info?.(`Running ${wave.length} agents in parallel: ${wave.map(a => a.name).join(', ')}`);
                const results = await Promise.allSettled(
                    wave.map(agent => this._runAgent(agent))
                );

                // Log any failures
                for (let i = 0; i < results.length; i++) {
                    if (results[i].status === 'rejected') {
                        this.logger?.error?.(`Agent ${wave[i].name} failed: ${results[i].reason?.message}`);
                    }
                }
            }

            // Check halt_on_critical after each wave
            if (this._haltedOnCritical) {
                this.logger?.warn?.('Scan halted after critical finding. Proceeding to synthesis.');
                break;
            }
        }

        // Cleanup all agents
        for (const [, agent] of this._agents) {
            try {
                await agent.cleanup();
            } catch (err) {
                this.logger?.debug?.(`Cleanup for ${agent.name}: ${err.message}`);
            }
        }

        // Synthesis phase
        const duration = Date.now() - this._startTime;
        const results = this._synthesize(duration);

        this.eventBus.emit('scan:completed', {
            timestamp: new Date().toISOString(),
            duration,
            totalFindings: this.ledger.count,
            haltedOnCritical: this._haltedOnCritical,
        });

        // Send webhook notification if configured
        if (this.config.notify_webhook) {
            await this._sendWebhook(results);
        }

        return results;
    }

    /**
     * Run a single agent with error boundary.
     */
    async _runAgent(agent) {
        try {
            await agent.run();

            // If this is the crawl agent, store surface inventory for downstream agents
            if (agent.name === 'JAKU-CRAWL' && this._sharedContext.surfaceInventory === null) {
                // The crawl agent should have set this
                this.logger?.debug?.('Surface inventory should be set by JAKU-CRAWL');
            }
        } catch (error) {
            // Agent errors are non-fatal — other agents continue
            this.logger?.error?.(`Agent ${agent.name} failed: ${error.message}`);
        }
    }

    /**
     * Resolve agents into execution waves based on dependencies.
     * Uses topological sort — agents in the same wave have no inter-dependencies.
     * 
     * Example:
     *   JAKU-CRAWL (no deps)    → Wave 1
     *   JAKU-QA (dep: CRAWL)    → Wave 2
     *   JAKU-SEC (dep: CRAWL)   → Wave 2 (parallel with QA)
     */
    _resolveExecutionOrder() {
        const waves = [];
        const completed = new Set();
        const remaining = new Map(this._agents);

        let iterations = 0;
        const maxIterations = remaining.size + 1;

        while (remaining.size > 0 && iterations < maxIterations) {
            iterations++;
            const currentWave = [];

            for (const [name, agent] of remaining) {
                const depsResolved = agent.dependencies.every(dep => completed.has(dep));
                if (depsResolved) {
                    currentWave.push(agent);
                }
            }

            if (currentWave.length === 0) {
                const stuck = [...remaining.keys()].join(', ');
                throw new Error(`Circular dependency detected among agents: ${stuck}`);
            }

            for (const agent of currentWave) {
                remaining.delete(agent.name);
                completed.add(agent.name);
            }

            waves.push(currentWave);
        }

        return waves;
    }

    /**
     * Synthesis phase — deduplicate, correlate, and build final report data.
     */
    _synthesize(duration) {
        const exported = this.ledger.export();

        // Build per-agent summary
        const agentSummaries = {};
        for (const [name, agent] of this._agents) {
            agentSummaries[name] = {
                status: agent.status,
                duration: agent.duration,
                findingsCount: agent.findings.length,
            };
        }

        return {
            findings: exported.findings,
            deduplicated: exported.deduplicated,
            summary: exported.summary,
            dedupSummary: exported.dedupSummary,
            dedupStats: exported.dedupStats,
            correlations: exported.correlations,
            agents: agentSummaries,
            surfaceInventory: this._sharedContext.surfaceInventory,
            duration,
            eventLog: this.eventBus.getLog(),
        };
    }

    /**
     * Get the status of all agents.
     */
    getStatus() {
        const status = {};
        for (const [name, agent] of this._agents) {
            status[name] = {
                status: agent.status,
                duration: agent.duration,
                findings: agent.findings.length,
            };
        }
        return status;
    }

    /**
     * Send scan results to configured webhook (Slack, Linear, PagerDuty, etc.)
     */
    async _sendWebhook(results) {
        const webhookUrl = this.config.notify_webhook;
        if (!webhookUrl) return;

        try {
            const payload = {
                agent: 'JAKU',
                version: '1.0.1',
                target: this.config.target_url,
                timestamp: new Date().toISOString(),
                duration: results.duration,
                totalFindings: results.findings?.length || 0,
                summary: results.summary,
                criticalCount: results.summary?.critical || 0,
                highCount: results.summary?.high || 0,
                haltedOnCritical: this._haltedOnCritical,
            };

            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(10000),
            });

            this.logger?.info?.(`Webhook notification sent to ${webhookUrl}`);
        } catch (err) {
            this.logger?.warn?.(`Webhook notification failed: ${err.message}`);
        }
    }
}

export default Orchestrator;
