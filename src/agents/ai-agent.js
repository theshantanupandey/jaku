import { BaseAgent } from './base-agent.js';
import { AIEndpointDetector } from '../core/ai/ai-endpoint-detector.js';
import { PromptInjector } from '../core/ai/prompt-injector.js';
import { JailbreakTester } from '../core/ai/jailbreak-tester.js';
import { SystemPromptExtractor } from '../core/ai/system-prompt-extractor.js';
import { OutputAnalyzer } from '../core/ai/output-analyzer.js';
import { GuardrailProber } from '../core/ai/guardrail-prober.js';
import { ModelDoSTester } from '../core/ai/model-dos-tester.js';
import { IndirectInjector } from '../core/ai/indirect-injector.js';
import { MultiTurnAttacker } from '../core/ai/multi-turn-attacker.js';
import { ModelFingerprinter } from '../core/ai/model-fingerprinter.js';

/**
 * JAKU-AI — Prompt Injection & AI Abuse Detection Agent
 * 
 * Pipeline:
 * 1. Detect AI endpoints (auto-discovery from surface inventory)
 * 2. Prompt Injection testing (many-shot, encoding, delimiter, context flood, RAG, CoT)
 * 3. Jailbreak testing (DAN, AIM, model-specific token attacks, persona anchoring)
 * 4. System Prompt Extraction (17 techniques)
 * 5. Output Analysis (AI-mediated XSS, markdown rendering attacks)
 * 6. Guardrail Probing (PII, agency, tool abuse, SSRF, agentic tool injection)
 * 7. Model DoS Testing (context bombing, token loops)
 * 8. Indirect Injection Testing (6 embedded payloads)
 * 9. Multi-Turn Attack Testing (trust escalation, context drift, memory poisoning)
 * 10. Model Fingerprinting + Model-Specific Exploits
 * 
 * Dependencies: JAKU-CRAWL (runs in Wave 2, parallel with QA + SEC)
 */
export class AIAgent extends BaseAgent {
    get name() { return 'JAKU-AI'; }
    get dependencies() { return ['JAKU-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — JAKU-CRAWL must run first');
        }

        // Phase 1: Detect AI endpoints
        this.progress('detect', 'Detecting AI-powered endpoints...', 0);

        const detector = new AIEndpointDetector(logger);
        const aiSurfaces = await detector.detect(surfaceInventory);

        this._log(`Detected ${aiSurfaces.length} AI surfaces (${aiSurfaces.filter(s => s.confidence === 'confirmed').length} confirmed)`);
        this.progress('detect', `Found ${aiSurfaces.length} AI endpoints`, 10);

        if (aiSurfaces.length === 0) {
            this._log('No AI endpoints detected — skipping AI abuse tests');
            this.progress('complete', 'No AI endpoints found — scan skipped', 100);
            return;
        }

        // Create shared sendMessage function for sub-modules
        const injector = new PromptInjector(logger);
        const sendMessage = injector._sendMessage.bind(injector);

        // Phase 2: Prompt Injection
        this.progress('injection', 'Testing for prompt injection...', 15);
        try {
            const injectionFindings = await injector.inject(aiSurfaces);
            this.addFindings(injectionFindings);
            this._log(`Prompt injection: ${injectionFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Prompt injection testing failed: ${err.message}`, 'error');
        }
        this.progress('injection', 'Prompt injection testing complete', 30);

        // Phase 3: Jailbreak Testing
        this.progress('jailbreak', 'Testing jailbreak techniques...', 30);
        try {
            const tester = new JailbreakTester(logger);
            const jailbreakFindings = await tester.test(aiSurfaces, sendMessage);
            this.addFindings(jailbreakFindings);
            this._log(`Jailbreak: ${jailbreakFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Jailbreak testing failed: ${err.message}`, 'error');
        }
        this.progress('jailbreak', 'Jailbreak testing complete', 50);

        // Phase 4: System Prompt Extraction
        this.progress('extraction', 'Attempting system prompt extraction...', 50);
        try {
            const extractor = new SystemPromptExtractor(logger);
            const extractionFindings = await extractor.extract(aiSurfaces, sendMessage);
            this.addFindings(extractionFindings);
            this._log(`System prompt extraction: ${extractionFindings.length} leaks`);
        } catch (err) {
            this._log(`System prompt extraction failed: ${err.message}`, 'error');
        }
        this.progress('extraction', 'System prompt extraction complete', 70);

        // Phase 5: Output Analysis (AI-mediated XSS)
        this.progress('output', 'Analyzing AI output sanitization...', 70);
        try {
            const analyzer = new OutputAnalyzer(logger);
            const outputFindings = await analyzer.analyze(aiSurfaces, sendMessage);
            this.addFindings(outputFindings);
            this._log(`Output analysis: ${outputFindings.length} issues`);
        } catch (err) {
            this._log(`Output analysis failed: ${err.message}`, 'error');
        }
        this.progress('output', 'Output analysis complete', 85);

        // Phase 6: Guardrail Probing
        this.progress('guardrails', 'Probing AI guardrails...', 85);
        try {
            const prober = new GuardrailProber(logger);
            const guardrailFindings = await prober.probe(aiSurfaces, sendMessage);
            this.addFindings(guardrailFindings);
            this._log(`Guardrails: ${guardrailFindings.length} bypasses`);
        } catch (err) {
            this._log(`Guardrail probing failed: ${err.message}`, 'error');
        }
        this.progress('guardrails', 'Guardrail probing complete', 80);

        // Phase 7: Model DoS
        this.progress('dos', 'Testing model DoS vectors...', 80);
        try {
            const dosTester = new ModelDoSTester(logger);
            const dosFindings = await dosTester.test(aiSurfaces, sendMessage);
            this.addFindings(dosFindings);
            this._log(`Model DoS: ${dosFindings.length} issues`);
        } catch (err) {
            this._log(`Model DoS testing failed: ${err.message}`, 'error');
        }
        this.progress('dos', 'Model DoS testing complete', 90);

        // Phase 8: Indirect Injection
        this.progress('indirect', 'Testing indirect prompt injection...', 90);
        try {
            const indirectInjector = new IndirectInjector(logger);
            const indirectFindings = await indirectInjector.test(aiSurfaces, sendMessage);
            this.addFindings(indirectFindings);
            this._log(`Indirect injection: ${indirectFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Indirect injection testing failed: ${err.message}`, 'error');
        }
        this.progress('indirect', 'Indirect injection testing complete', 95);

        // Phase 9: Multi-Turn Attack Testing
        this.progress('multiturn', 'Running multi-turn attack scenarios...', 95);
        try {
            const injector = new PromptInjector(logger);
            const sendMsg = injector._sendMessage.bind(injector);
            const multiTurnAttacker = new MultiTurnAttacker(logger);
            const multiTurnFindings = await multiTurnAttacker.test(aiSurfaces, sendMsg);
            this.addFindings(multiTurnFindings);
            this._log(`Multi-turn attacks: ${multiTurnFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Multi-turn testing failed: ${err.message}`, 'error');
        }
        this.progress('multiturn', 'Multi-turn attack testing complete', 97);

        // Phase 10: Model Fingerprinting + Model-Specific Exploits
        this.progress('fingerprint', 'Fingerprinting model and running model-specific attacks...', 97);
        try {
            const injector2 = new PromptInjector(logger);
            const sendMsg2 = injector2._sendMessage.bind(injector2);
            const fingerprinter = new ModelFingerprinter(logger);
            const fingerprintFindings = await fingerprinter.test(aiSurfaces, sendMsg2);
            this.addFindings(fingerprintFindings);
            this._log(`Model fingerprinting: ${fingerprintFindings.length} findings`);
        } catch (err) {
            this._log(`Model fingerprinting failed: ${err.message}`, 'error');
        }
        this.progress('fingerprint', 'Model fingerprinting complete', 100);

        this.progress('complete', `AI scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default AIAgent;
