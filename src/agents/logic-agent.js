import { BaseAgent } from './base-agent.js';
import { BusinessRuleInferrer } from '../core/logic/business-rule-inferrer.js';
import { PricingExploiter } from '../core/logic/pricing-exploiter.js';
import { AccessBoundaryTester } from '../core/logic/access-boundary-tester.js';
import { WorkflowEnforcer } from '../core/logic/workflow-enforcer.js';
import { RaceConditionDetector } from '../core/logic/race-condition-detector.js';
import { AbusePatternScanner } from '../core/logic/abuse-pattern-scanner.js';
import { GraphQLAuditor } from '../core/logic/graphql-auditor.js';
import { ParameterPolluter } from '../core/logic/parameter-polluter.js';

/**
 * JAKU-LOGIC — Business Logic Validation Agent
 *
 * Pipeline (8 phases):
 * 1. Infer business rules from surface inventory
 * 2. Test pricing/payment manipulation
 * 3. Test access control boundaries (IDOR, JWT sub, cross-tenant, UUID enumeration)
 * 4. Test workflow enforcement (step skipping, resubmission, invalid transitions)
 * 5. Test race conditions (double spend, TOCTOU, inventory oversell)
 * 6. Test abuse patterns (referral, reward, subscription farming)
 * 7. GraphQL security audit (introspection, batch, depth, aliases, field suggestions)
 * 8. HTTP parameter pollution (duplication, injection, verb tampering)
 *
 * Dependencies: JAKU-CRAWL (runs in Wave 2, parallel with QA + SEC + AI)
 */
export class LogicAgent extends BaseAgent {
    get name() { return 'JAKU-LOGIC'; }
    get dependencies() { return ['JAKU-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — JAKU-CRAWL must run first');
        }

        // Phase 1: Infer business rules
        this.progress('infer', 'Inferring business rules from surface inventory...', 0);

        const inferrer = new BusinessRuleInferrer(logger);
        const businessContext = inferrer.infer(surfaceInventory);

        const activeDomains = Object.entries(businessContext.domains)
            .filter(([, items]) => items.length > 0)
            .map(([domain]) => domain);

        this._log(`Inferred ${activeDomains.length} business domains: ${activeDomains.join(', ') || 'none'}`);
        this.progress('infer', `Found ${activeDomains.length} business domains`, 10);

        if (activeDomains.length === 0) {
            this._log('No business logic surfaces detected — skipping logic tests');
            this.progress('complete', 'No business logic surfaces found — scan skipped', 100);
            return;
        }

        // Phase 2: Pricing exploitation
        this.progress('pricing', 'Testing pricing & payment logic...', 10);
        try {
            const exploiter = new PricingExploiter(logger);
            const pricingFindings = await exploiter.exploit(businessContext);
            this.addFindings(pricingFindings);
            this._log(`Pricing: ${pricingFindings.length} issues`);
        } catch (err) {
            this._log(`Pricing testing failed: ${err.message}`, 'error');
        }
        this.progress('pricing', 'Pricing testing complete', 25);

        // Phase 3: Access boundary testing
        this.progress('access', 'Testing access control boundaries...', 25);
        try {
            const tester = new AccessBoundaryTester(logger);
            const accessFindings = await tester.test(businessContext, surfaceInventory);
            this.addFindings(accessFindings);
            this._log(`Access: ${accessFindings.length} issues`);
        } catch (err) {
            this._log(`Access boundary testing failed: ${err.message}`, 'error');
        }
        this.progress('access', 'Access boundary testing complete', 45);

        // Phase 4: Workflow enforcement
        this.progress('workflow', 'Testing workflow enforcement...', 45);
        try {
            const enforcer = new WorkflowEnforcer(logger);
            const workflowFindings = await enforcer.enforce(businessContext, surfaceInventory);
            this.addFindings(workflowFindings);
            this._log(`Workflow: ${workflowFindings.length} issues`);
        } catch (err) {
            this._log(`Workflow testing failed: ${err.message}`, 'error');
        }
        this.progress('workflow', 'Workflow testing complete', 65);

        // Phase 5: Race condition detection
        this.progress('race', 'Testing for race conditions...', 65);
        try {
            const detector = new RaceConditionDetector(logger);
            const raceFindings = await detector.detect(businessContext, surfaceInventory);
            this.addFindings(raceFindings);
            this._log(`Race conditions: ${raceFindings.length} issues`);
        } catch (err) {
            this._log(`Race condition testing failed: ${err.message}`, 'error');
        }
        this.progress('race', 'Race condition testing complete', 85);

        // Phase 6: Abuse pattern scanning
        this.progress('abuse', 'Scanning for abuse patterns...', 85);
        try {
            const scanner = new AbusePatternScanner(logger);
            const abuseFindings = await scanner.scan(businessContext, surfaceInventory);
            this.addFindings(abuseFindings);
            this._log(`Abuse patterns: ${abuseFindings.length} issues`);
        } catch (err) {
            this._log(`Abuse pattern scanning failed: ${err.message}`, 'error');
        }
        this.progress('abuse', 'Abuse pattern scanning complete', 85);

        // Phase 7: GraphQL Security Audit
        this.progress('graphql', 'Auditing GraphQL endpoints...', 85);
        try {
            const gqlAuditor = new GraphQLAuditor(logger);
            const gqlFindings = await gqlAuditor.audit(surfaceInventory);
            this.addFindings(gqlFindings);
            this._log(`GraphQL: ${gqlFindings.length} issues`);
        } catch (err) {
            this._log(`GraphQL audit failed: ${err.message}`, 'error');
        }
        this.progress('graphql', 'GraphQL audit complete', 92);

        // Phase 8: HTTP Parameter Pollution
        this.progress('hpp', 'Testing HTTP parameter pollution...', 92);
        try {
            const polluter = new ParameterPolluter(logger);
            const hppFindings = await polluter.pollute(businessContext, surfaceInventory);
            this.addFindings(hppFindings);
            this._log(`Parameter pollution: ${hppFindings.length} issues`);
        } catch (err) {
            this._log(`Parameter pollution testing failed: ${err.message}`, 'error');
        }
        this.progress('hpp', 'Parameter pollution testing complete', 100);

        this.progress('complete', `Logic scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default LogicAgent;
