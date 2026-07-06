'use strict';

/**
 * CRA (EU Cyber Resilience Act, Regulation (EU) 2024/2847) readiness —
 * evidence & gap analysis from a scan.
 *
 * Citations are to the FINAL adopted Regulation (in force), NOT the 2022
 * proposal — the two number Annex I differently. Text shown in "quotes" is
 * verbatim from the Regulation; unquoted clause descriptions are plain-language
 * summaries. A wrong verbatim citation is worse than none, so only text
 * confirmed against the adopted Annex I is quoted.
 *
 * This makes NO conformity claim. It maps what a repository scan can evidence
 * to CRA requirements, is loud about what a scan cannot determine, and never
 * prints a PASS on a legal requirement. Three honest kinds of clause:
 *   evidence     — a scan produces auditor-usable evidence
 *   review       — a scan surfaces evidence relevant to a clause but cannot
 *                  determine conformity (e.g. "known" ≠ "exploitable")
 *   process/legal— an obligation outside anything a scan can observe
 */

const fs = require('fs');
const path = require('path');

const SECURITY_POLICY_PATHS = [
    'SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md',
    'security.txt', '.well-known/security.txt',
];

function hasSecurityPolicy(dir) {
    if (!dir) return false;
    return SECURITY_POLICY_PATHS.some((p) => {
        try { return fs.existsSync(path.join(dir, p)); } catch { return false; }
    });
}

function assessCRA(result, opts = {}) {
    const stats = result.stats || {};
    const lc    = stats.licenseCompliance || {};
    const dir   = opts.dir;

    const componentCount = stats.totalComponents ?? (result.components || []).length;
    const knownVulns     = stats.vulnerabilities ?? 0;
    const criticalVulns  = stats.critical ?? 0;
    const undocumented   = (lc.unknown || []).length;
    const forbidden      = (lc.forbidden || []).length;
    const dockerFindings = stats.dockerFindings ?? 0;
    const dockerHigh     = stats.dockerHigh ?? 0;
    const policyPresent  = hasSecurityPolicy(dir);
    const hasSBOM        = !!(result.cyclonedx || result.spdx);
    const kevCount       = opts.kevCount ?? null; // null on the free CLI path

    const clauses = [];
    // verbatim=true → `text` is quoted from the adopted Regulation.
    // verbatim=false → `text` is our plain-language summary of the obligation.
    const add = (bucket, cite, text, verbatim, detail) =>
        clauses.push({ bucket, cite, text, verbatim, detail });

    // ── Scan evidence — Annex I, Part II (vulnerability handling) ────────────
    add(hasSBOM ? 'evidence' : 'review',
        'Annex I, Part II, point (1)',
        'identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products',
        true,
        hasSBOM
            ? `Generated CycloneDX 1.6 and SPDX 2.3 covering ${componentCount} components (the full resolved tree, beyond the "top-level" floor). This SBOM is also a required element of the Annex VII technical documentation (point 2(b)).`
            : 'No SBOM was produced for this project.');

    // Coordinated disclosure policy (5, verbatim) + reporting contact (6, summary)
    // — both evidenced by the same scannable artifact.
    add(policyPresent ? 'evidence' : 'review',
        'Annex I, Part II, points (5) & (6) — coordinated disclosure & reporting contact',
        'put in place and enforce a policy on coordinated vulnerability disclosure',
        true,
        `Point (6): "take measures to facilitate the sharing of information about potential vulnerabilities … including by providing a contact address for the reporting of the vulnerabilities discovered in the product with digital elements". Both are evidenced by a SECURITY.md / security.txt — ${policyPresent ? 'present in this project.' : 'NOT found; add one.'}`);

    // Component licensing → technical documentation.
    add((undocumented === 0 && forbidden === 0) ? 'evidence' : 'review',
        'Annex VII — technical documentation (component licensing)',
        'the technical file must describe the product and its components, including their licensing',
        false,
        `${undocumented} components with undocumented (NOASSERTION) licenses`
            + (forbidden ? `, ${forbidden} under a forbidden license` : '')
            + (undocumented === 0 && forbidden === 0 ? '. All components carry a documented license.' : ' — resolve for a complete technical file.'));

    // ── Review / signal — evidence relevant, but not conformity ─────────────
    add('review',
        'Annex I, Part I, point (2)(a)',
        'be made available on the market without known exploitable vulnerabilities',
        true,
        craVulnEvidence(knownVulns, criticalVulns, kevCount));

    add('review',
        'Annex I, Part I, point (2)(j)',
        'be designed, developed and produced to limit attack surfaces, including external interfaces',
        true,
        dockerFindings > 0
            ? `Static evidence only: Dockerfile audit flagged ${dockerFindings} issue(s)${dockerHigh ? ` (${dockerHigh} high)` : ''} and the dependency footprint is inventoried. Runtime interfaces, exposed services and deployed configuration are NOT assessed.`
            : 'Static evidence only: the dependency footprint is inventoried. Runtime external interfaces and deployed configuration are NOT assessed by a scan.');

    // ── Not verifiable — process obligations (Annex I, Part II) ─────────────
    add('process', 'Annex I, Part II, point (2)',
        'address and remediate vulnerabilities without delay, including by providing security updates; where technically feasible, new security updates shall be provided separately from functionality updates',
        true,
        'A process, not a code property. A point-in-time scan lists what to remediate but cannot prove your remediation cadence — the auditor will ask for patch history / tickets.');

    add('process', 'Annex I, Part II, point (3)',
        'apply effective and regular tests and reviews of the security of the product',
        true,
        'A process a scan cannot observe. Running sbomix in CI partially evidences the "regular testing" duty.');

    add('process', 'Annex I, Part II, point (4)',
        'share and publicly disclose information about fixed vulnerabilities',
        true,
        'Once an update is available: disclosure of what you already fixed (distinct from the coordinated-disclosure policy in (5)). Not observable from a repository scan.');

    add('process', 'Annex I, Part II, point (7)',
        'provide for mechanisms to securely distribute updates',
        true,
        'An update-delivery mechanism a scan cannot verify.');

    add('process', 'Annex I, Part II, point (8)',
        'ensure that, where security updates are available to address identified security issues, they are disseminated without delay and, unless otherwise agreed between a manufacturer and a business user in relation to a tailor-made product with digital elements, free of charge, accompanied by advisory messages providing users with the relevant information, including on potential action to be taken',
        true,
        'Update dissemination timeliness, cost and advisories — not observable from a scan.');

    add('process', 'Article 14 — reporting obligations (from 11 Sept 2026)',
        'requires manufacturers to notify actively exploited vulnerabilities and severe incidents to the CSIRT designated as coordinator and to ENISA',
        false,
        'An operational reporting duty. Purely process — a scan cannot evidence it.');

    // ── Not verifiable — legal / documentation & classification ─────────────
    add('legal', 'Article 28 & Annex V — EU declaration of conformity',
        'requires a written EU declaration of conformity, retained for 10 years or the support period',
        false,
        'A legal declaration. No scan produces or verifies it.');

    add('legal', 'Article 30 (CE marking); Article 32 & Annex VIII (conformity assessment)',
        'the CE marking is affixed following the conformity assessment required by Article 32 (procedures — modules A/B/C/H — in Annex VIII)',
        false,
        'A legal act following conformity assessment. A scanner has nothing to say about CE eligibility.');

    add('legal', 'Annex VII, point 2(b) — technical documentation',
        'the software bill of materials, the coordinated vulnerability disclosure policy, evidence of the provision of a contact address … and a description of the technical solutions chosen for the secure distribution of updates',
        true,
        'The 10-year technical file. A scan cannot assemble it — but your generated SBOM and disclosure policy are two of its required contents (quoted above).');

    add('legal', 'Annex III / Annex IV — product classification',
        'classifies certain products as important (Class I / II) or critical, which decides whether self-assessment is even allowed',
        false,
        'A LEGAL determination based on what the product does — have a human review classification. sbomix does not and will not assign a class.');

    const by = (b) => clauses.filter((c) => c.bucket === b);
    return {
        clauses,
        summary: {
            total:         clauses.length,
            scanEvidence:  by('evidence').length,
            review:        by('review').length,
            notVerifiable: by('process').length + by('legal').length,
        },
        disclaimer:
            'cra-check maps observable repository evidence to CRA Annex I requirements. It identifies '
            + 'evidence and gaps. It is NOT a conformity assessment, a declaration of conformity, or legal '
            + 'advice, and it does not determine CE-marking eligibility. Quoted text is verbatim from '
            + 'Regulation (EU) 2024/2847; unquoted clause descriptions are summaries.',
    };
}

// (2)(a) is never a PASS from a zero-CVE count: zero known CVEs today is not
// conformity, and "known" is not "exploitable". Tiered evidence statement.
function craVulnEvidence(knownVulns, criticalVulns, kevCount) {
    const base = knownVulns === 0
        ? 'No known vulnerabilities detected in dependencies at scan time.'
        : `${knownVulns} known vulnerabilities detected in dependencies (${criticalVulns} critical).`;

    let kev = '';
    if (kevCount !== null && kevCount > 0) {
        kev = ` ${kevCount} appear on the CISA KEV catalogue (actively exploited) — a strong negative signal against (2)(a).`;
    } else if (kevCount === null) {
        kev = ' The free CLI has no exploited-in-the-wild feed; CISA KEV enrichment (hosted scan / --explain) upgrades this from "known" to "known exploited".';
    }

    return base + kev
        + ' This is evidence relevant to (2)(a), NOT a determination that the product is free of known exploitable vulnerabilities — that requires exploitability assessment, and the obligation is ongoing across the support period.';
}

// Plain-language, three-bucket report for the CLI.
function formatCRAReport(assessment, projectName) {
    const { clauses, summary, disclaimer } = assessment;
    const out = [];
    out.push('');
    out.push(`  CRA readiness — ${projectName}`);
    out.push('  (EU Cyber Resilience Act, Reg. (EU) 2024/2847 — evidence & gap analysis, not a conformity assessment)');
    out.push('');

    const bucket = (title, items) => {
        if (items.length === 0) return;
        out.push(`  ${title}`);
        for (const c of items) {
            out.push(`    • ${c.cite}`);
            out.push(c.verbatim ? `        "${c.text}"` : `        ${c.text}`);
            out.push(`        → ${c.detail}`);
        }
        out.push('');
    };

    bucket('✓ SCAN EVIDENCE (auditor-usable)',
        clauses.filter((c) => c.bucket === 'evidence'));
    bucket('▲ REVIEW / GAPS — evidence relevant, but not conformity',
        clauses.filter((c) => c.bucket === 'review'));
    bucket('○ NOT VERIFIABLE BY A SCAN — you must evidence these yourself',
        clauses.filter((c) => c.bucket === 'process' || c.bucket === 'legal'));

    out.push(`  Summary: ${summary.scanEvidence} scan evidence · ${summary.review} to review · ${summary.notVerifiable} not scan-verifiable`);
    out.push('');
    out.push(`  ${disclaimer}`);
    out.push('');
    return out.join('\n');
}

module.exports = { assessCRA, formatCRAReport, hasSecurityPolicy };
