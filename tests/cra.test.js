'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { assessCRA, formatCRAReport, hasSecurityPolicy } = require('../src/cra');

function scan({ components = 10, vulns = 0, critical = 0, unknown = 0, sbom = true } = {}) {
    return {
        cyclonedx: sbom ? {} : null,
        spdx: sbom ? {} : null,
        stats: {
            totalComponents: components,
            vulnerabilities: vulns,
            critical,
            licenseCompliance: { unknown: Array(unknown).fill({}), forbidden: [] },
        },
    };
}

const clauseByCite = (a, cite) => a.clauses.find((c) => c.cite === cite);

describe('cra-check — Annex I citations', () => {
    test('no-known-exploitable-vulns cites Part I point (2)(a), not a vague "Part I"', () => {
        const a = assessCRA(scan());
        assert.ok(clauseByCite(a, 'Annex I, Part I, point (2)(a)'), '(2)(a) citation missing/incorrect');
    });

    test('attack surface cites Part I point (2)(j)', () => {
        const a = assessCRA(scan());
        assert.ok(clauseByCite(a, 'Annex I, Part I, point (2)(j)'), '(2)(j) citation missing/incorrect');
    });

    test('all eight Part II points are acknowledged (1..8)', () => {
        const a = assessCRA(scan());
        const cites = a.clauses.map((c) => c.cite).join(' | ');
        for (const p of [1, 2, 3, 4, 7, 8]) {
            assert.ok(cites.includes(`Part II, point (${p})`), `Part II point (${p}) not named`);
        }
        assert.ok(cites.includes('points (5) & (6)'), 'Part II points (5)&(6) not named');
    });
});

describe('cra-check — (2)(a) is never a PASS', () => {
    test('with zero CVEs, (2)(a) stays in REVIEW, never in SCAN EVIDENCE', () => {
        const c = clauseByCite(assessCRA(scan({ vulns: 0 })), 'Annex I, Part I, point (2)(a)');
        assert.equal(c.bucket, 'review', 'zero CVEs must not become auditor-ready evidence');
    });

    test('(2)(a) detail explicitly disclaims conformity', () => {
        const c = clauseByCite(assessCRA(scan({ vulns: 0 })), 'Annex I, Part I, point (2)(a)');
        assert.match(c.detail, /NOT a determination/, 'must not imply a conformity pass');
        assert.doesNotMatch(c.detail, /\bpass\b/i);
    });

    test('KEV enrichment upgrades the claim when supplied', () => {
        const withKev = assessCRA(scan({ vulns: 5, critical: 1 }), { kevCount: 2 });
        const c = clauseByCite(withKev, 'Annex I, Part I, point (2)(a)');
        assert.match(c.detail, /KEV catalogue \(actively exploited\)/);
    });
});

describe('cra-check — evidence bucketing', () => {
    test('SBOM is auditor-usable scan evidence when produced', () => {
        const c = clauseByCite(assessCRA(scan({ sbom: true })), 'Annex I, Part II, point (1)');
        assert.equal(c.bucket, 'evidence');
        assert.equal(c.verbatim, true, 'the SBOM clause text is quoted verbatim');
    });

    test('legal obligations (DoC, CE, technical file, classification) are named as not-verifiable', () => {
        const cites = assessCRA(scan()).clauses.map((c) => c.cite).join(' | ');
        assert.ok(cites.includes('Article 28'), 'Declaration of Conformity not named');
        assert.ok(cites.includes('Article 30'), 'CE marking not named');
        assert.ok(cites.includes('Annex VII'), 'technical documentation not named');
        assert.ok(cites.includes('Annex III / Annex IV'), 'classification not named');
        assert.ok(cites.includes('Article 14'), 'Article 14 reporting not named');
    });

    test('the report never claims to determine a class', () => {
        const c = clauseByCite(assessCRA(scan()), 'Annex III / Annex IV — product classification');
        assert.match(c.detail, /does not and will not assign a class/);
    });
});

describe('cra-check — security policy detection', () => {
    test('detects SECURITY.md and .well-known/security.txt', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-'));
        assert.equal(hasSecurityPolicy(dir), false);
        fs.writeFileSync(path.join(dir, 'SECURITY.md'), '# security');
        assert.equal(hasSecurityPolicy(dir), true);
        fs.rmSync(dir, { recursive: true, force: true });
    });

    test('a present policy moves (5)&(6) into scan evidence', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cra-'));
        fs.writeFileSync(path.join(dir, 'SECURITY.md'), '# security');
        const c = assessCRA(scan(), { dir }).clauses.find((x) => x.cite.includes('points (5) & (6)'));
        assert.equal(c.bucket, 'evidence');
        fs.rmSync(dir, { recursive: true, force: true });
    });
});

describe('cra-check — report format', () => {
    test('disclaimer matches the AI-BOM posture (not a conformity assessment) and marks verbatim vs summary', () => {
        const text = formatCRAReport(assessCRA(scan()), 'demo');
        assert.match(text, /NOT a conformity assessment/);
        assert.match(text, /Quoted text is verbatim/);
    });
});
