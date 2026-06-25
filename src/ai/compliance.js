'use strict';

/**
 * Regulatory alignment for the AI BOM.
 *
 * Maps the AI BOM's evidence (lineage, signatures, threat findings) to specific
 * clauses of two regimes:
 *
 *   • ISO/IEC 42001:2023 — AI Management System (AIMS). The certifiable standard
 *     for governing AI across its lifecycle. Relevant Annex A controls concern
 *     data provenance, system lifecycle records, and third-party/supplier risk.
 *
 *   • EU AI Act, Article 12 — "Record-keeping". High-risk AI systems must
 *     technically allow automatic recording of events (logs) over the system's
 *     lifetime, traceable to data sources and model versions. The signed lineage
 *     chain is the artifact that demonstrates this traceability.
 *
 * This module does NOT claim certification. It produces an evidence-to-control
 * map an auditor can use, and flags gaps where the BOM lacks the evidence a
 * control expects.
 */

// Control catalogue — the subset each piece of AI BOM evidence speaks to.
const CONTROLS = {
    'ISO42001:A.7.2': {
        regime: 'ISO/IEC 42001:2023',
        title:  'Data provenance and quality (Annex A.7 — Data for AI systems)',
        expects: 'documented origin and lineage of training/fine-tuning data',
        evidence: 'lineage.dataset',
    },
    'ISO42001:A.7.4': {
        regime: 'ISO/IEC 42001:2023',
        title:  'Data provenance recording',
        expects: 'recorded provenance for each data source used',
        evidence: 'lineage.dataset',
    },
    'ISO42001:A.6.2.4': {
        regime: 'ISO/IEC 42001:2023',
        title:  'AI system verification and validation',
        expects: 'evaluation/verification records prior to deployment',
        evidence: 'lineage.evaluation',
    },
    'ISO42001:A.6.2.6': {
        regime: 'ISO/IEC 42001:2023',
        title:  'AI system deployment records',
        expects: 'records of what model version was promoted to production',
        evidence: 'lineage.deploy',
    },
    'ISO42001:A.10.2': {
        regime: 'ISO/IEC 42001:2023',
        title:  'Allocation of responsibilities with suppliers/third parties',
        expects: 'inventory of third-party models, datasets, and AI services',
        evidence: 'inventory.thirdParty',
    },
    'ISO42001:A.10.3': {
        regime: 'ISO/IEC 42001:2023',
        title:  'Supplier and third-party AI components',
        expects: 'supply-chain risk assessment for imported pretrained models',
        evidence: 'threats.supplyChain',
    },
    'EUAIACT:Art12.1': {
        regime: 'EU AI Act (Reg. 2024/1689)',
        title:  'Article 12(1) — Automatic recording of events (logs) over lifetime',
        expects: 'lifecycle event log enabling traceability',
        evidence: 'lineage.chain',
    },
    'EUAIACT:Art12.2': {
        regime: 'EU AI Act (Reg. 2024/1689)',
        title:  'Article 12(2) — Traceability appropriate to intended purpose',
        expects: 'tamper-evident lineage linking outputs to model + data versions',
        evidence: 'lineage.integrity',
    },
    'EUAIACT:Art12.3': {
        regime: 'EU AI Act (Reg. 2024/1689)',
        title:  'Article 12(3) — Recording of reference data and version identification',
        expects: 'cryptographic identification of dataset and model versions',
        evidence: 'lineage.signature',
    },
    'EUAIACT:Art15': {
        regime: 'EU AI Act (Reg. 2024/1689)',
        title:  'Article 15 — Accuracy, robustness and cybersecurity',
        expects: 'controls against model/data tampering and poisoning',
        evidence: 'threats.tampering',
    },
};

/**
 * Assess the AI BOM against the control catalogue.
 *
 * @param {object} ctx
 * @param {object[]} ctx.aiComponents - components with ecosystem==='ai'
 * @param {object[]} ctx.threats      - AI threat findings (from aibom.js)
 * @param {object[]} ctx.lineage      - hash-chained lineage records
 * @param {object}   ctx.lineageVerify - result of verifyLineage()
 * @param {object}   ctx.signature    - JSF signature block (or null)
 * @returns {{ regimes: string[], controls: object[], summary: object }}
 */
function assessCompliance({ aiComponents = [], threats = [], lineage = [], lineageVerify = null, signature = null }) {
    const hasStage   = (s) => lineage.some((r) => r.stage === s);
    const threatIds  = new Set(threats.map((t) => t.id));
    const thirdParty = aiComponents.filter((c) =>
        ['huggingface', 'api-provider'].includes(c.aiMetadata?.source) ||
        c.aiMetadata?.role === 'api-provider' || c.aiMetadata?.source === 'huggingface');

    // evidence key → { satisfied, detail }
    const evidence = {
        'lineage.dataset':    has(hasStage('dataset'),  'dataset stage recorded in lineage', 'no dataset provenance in lineage'),
        'lineage.evaluation': has(hasStage('evaluation'), 'evaluation stage recorded', 'no evaluation/validation record'),
        'lineage.deploy':     has(hasStage('deploy'),    'deploy stage recorded', 'no deployment record'),
        'lineage.chain':      has(lineage.length > 0,    `${lineage.length} lifecycle records`, 'no lifecycle event log'),
        'lineage.integrity':  has(!!lineageVerify?.valid, 'lineage hash chain verified intact', 'lineage chain missing or broken'),
        'lineage.signature':  has(isSigned(signature),   `signed (${sigDesc(signature)})`, 'lineage not cryptographically signed'),
        'inventory.thirdParty': has(thirdParty.length > 0, `${thirdParty.length} third-party AI components inventoried`, 'no third-party AI components detected/inventoried'),
        'threats.supplyChain': has(threatIds.has('AI-004') || threatIds.has('AI-005'), 'supply-chain provenance risks assessed', 'supply-chain risk not assessed'),
        'threats.tampering':   has(threatIds.has('AI-001') || threatIds.has('AI-002') || threatIds.has('AI-003'), 'tampering/poisoning risks assessed', 'tampering risk not assessed'),
    };

    const controls = Object.entries(CONTROLS).map(([id, c]) => {
        const ev = evidence[c.evidence] || has(false, '', 'no evidence mapping');
        return {
            control: id,
            regime:  c.regime,
            title:   c.title,
            expects: c.expects,
            status:  ev.satisfied ? 'satisfied' : 'gap',
            detail:  ev.detail,
        };
    });

    const satisfied = controls.filter((c) => c.status === 'satisfied').length;
    const regimes   = [...new Set(controls.map((c) => c.regime))];

    return {
        regimes,
        controls,
        summary: {
            total:        controls.length,
            satisfied,
            gaps:         controls.length - satisfied,
            coveragePct:  Math.round((satisfied / controls.length) * 100),
            disclaimer:   'Evidence-to-control mapping only. Not a certification or legal conformity assessment.',
        },
    };
}

function has(satisfied, okDetail, gapDetail) {
    return { satisfied, detail: satisfied ? okDetail : gapDetail };
}
function isSigned(sig) {
    return !!(sig && sig.value);
}
function sigDesc(sig) {
    if (!sig) return 'none';
    const pqc = sig.pqc?.status === 'unavailable' ? 'classical-only'
              : sig.pqc ? `hybrid+${sig.pqc.algorithm}` : 'classical';
    return `${sig.algorithm}, ${pqc}`;
}

module.exports = { assessCompliance, CONTROLS };
