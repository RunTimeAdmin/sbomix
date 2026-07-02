'use strict';

/**
 * Known-bad package matching for the crypto-agent report profile.
 *
 * Two independent checks:
 *   1. Exact match against KNOWN_BAD — a versioned, curated list. Ships empty
 *      by design: naming a specific package "known bad" without verified,
 *      current threat intelligence is a liability, not a feature. This is the
 *      mechanism; the list is a weekly curation task (see spec: "Maintenance
 *      rule: one hour per week").
 *   2. Typosquat proximity — flags a component name that's suspiciously close
 *      (edit distance) to a well-known signing/wallet library name. This is a
 *      naming-similarity signal ("worth a look"), not an accusation.
 *
 * KNOWN_BAD_LIST_VERSION is printed on every report so a stale list is
 * visible rather than silently trusted.
 */

const { SIGNING_PACKAGES } = require('./signingSurface');

const KNOWN_BAD_LIST_VERSION = '2026-07-02-seed';

/**
 * Curated known-bad/malicious package entries.
 * Schema: { ecosystem, name, reason, source }
 * Empty seed — populate via curation, not invention. See module docstring.
 */
const KNOWN_BAD = [];

const KNOWN_BAD_LOOKUP = new Set(
    KNOWN_BAD.map((e) => `${e.ecosystem}:${e.name.toLowerCase()}`)
);

function checkExactMatches(components) {
    const hits = [];
    for (const comp of components) {
        const key = `${comp.ecosystem}:${comp.name.toLowerCase()}`;
        if (KNOWN_BAD_LOOKUP.has(key)) {
            const entry = KNOWN_BAD.find(
                (e) => e.ecosystem === comp.ecosystem && e.name.toLowerCase() === comp.name.toLowerCase()
            );
            hits.push({ name: comp.name, version: comp.version, ecosystem: comp.ecosystem, purl: comp.purl, reason: entry.reason, source: entry.source });
        }
    }
    return hits;
}

// Iterative Levenshtein distance — package names are short, no need for anything fancier.
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
        const row = [i];
        for (let j = 1; j <= n; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            row[j] = Math.min(row[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
        }
        prev = row;
    }
    return prev[n];
}

// Reference set of well-known names to typosquat-check against, per ecosystem.
const REFERENCE_NAMES = {};
for (const [ecosystem, entries] of Object.entries(SIGNING_PACKAGES)) {
    REFERENCE_NAMES[ecosystem] = entries.map((e) => e.name);
}

const MAX_TYPOSQUAT_DISTANCE = 2;
const MIN_NAME_LENGTH_FOR_CHECK = 4; // skip very short names — distance-2 on a 3-char name is meaningless

function checkTyposquat(components) {
    const hits = [];
    for (const comp of components) {
        if (comp.name.length < MIN_NAME_LENGTH_FOR_CHECK) continue;
        const refs = REFERENCE_NAMES[comp.ecosystem];
        if (!refs) continue;
        for (const ref of refs) {
            if (comp.name === ref) continue; // exact match is a real dependency, not a typosquat
            const dist = levenshtein(comp.name.toLowerCase(), ref.toLowerCase());
            if (dist > 0 && dist <= MAX_TYPOSQUAT_DISTANCE) {
                hits.push({
                    name: comp.name, version: comp.version, ecosystem: comp.ecosystem, purl: comp.purl,
                    similarTo: ref, distance: dist,
                });
                break; // one flag per component is enough
            }
        }
    }
    return hits;
}

/**
 * Run both known-bad checks against a project's components.
 * @param {object[]} components
 * @returns {{ listVersion: string, exactMatches: object[], typosquatMatches: object[] }}
 */
function checkKnownBad(components) {
    return {
        listVersion: KNOWN_BAD_LIST_VERSION,
        exactMatches: checkExactMatches(components),
        typosquatMatches: checkTyposquat(components),
    };
}

module.exports = { checkKnownBad, KNOWN_BAD_LIST_VERSION, KNOWN_BAD, levenshtein };
