'use strict';

/**
 * Diff two component lists (pipeline objects or CycloneDX component arrays).
 * Each entry needs at minimum { purl, name, version }.
 *
 * @param {object[]} oldList
 * @param {object[]} newList
 * @returns {{ summary, added, removed, updated }}
 */
function diffComponents(oldList, newList) {
    const oldMap = new Map(oldList.map(c => [c.purl, c]));
    const newMap = new Map(newList.map(c => [c.purl, c]));

    const added   = [];
    const removed = [];
    const updated = [];

    for (const [purl, comp] of newMap) {
        const old = oldMap.get(purl);
        if (!old) {
            added.push({ purl, name: comp.name, version: comp.version, ecosystem: comp.ecosystem });
        } else if (old.version !== comp.version) {
            updated.push({ purl, name: comp.name, from: old.version, to: comp.version });
        }
    }
    for (const [purl, comp] of oldMap) {
        if (!newMap.has(purl)) {
            removed.push({ purl, name: comp.name, version: comp.version, ecosystem: comp.ecosystem });
        }
    }

    return {
        summary: { added: added.length, removed: removed.length, updated: updated.length },
        added,
        removed,
        updated,
    };
}

/**
 * Diff two vulnerability sets.
 * Each entry needs { purl (or component_purl), osv_id, severity }.
 *
 * @param {object[]} oldVulns
 * @param {object[]} newVulns
 * @returns {{ introduced, resolved }}
 */
function diffVulns(oldVulns, newVulns) {
    const key = v => `${v.purl ?? v.component_purl}::${v.osv_id}`;
    const oldKeys = new Set(oldVulns.map(key));
    const newKeys = new Set(newVulns.map(key));

    return {
        introduced: newVulns.filter(v => !oldKeys.has(key(v))),
        resolved:   oldVulns.filter(v => !newKeys.has(key(v))),
    };
}

/**
 * Full diff: components + vulnerabilities.
 * Convenience wrapper used by the CLI when comparing two local CycloneDX files.
 *
 * @param {object} oldCdx  - parsed CycloneDX JSON (older)
 * @param {object} newCdx  - parsed CycloneDX JSON (newer)
 * @returns {{ summary, added, removed, updated, introduced, resolved }}
 */
function diffCycloneDX(oldCdx, newCdx) {
    const oldComps = (oldCdx.components || []).filter(c => c.purl);
    const newComps = (newCdx.components || []).filter(c => c.purl);
    const compDiff = diffComponents(oldComps, newComps);

    // Flatten vulns from top-level vulnerabilities array (CycloneDX 1.6)
    const flattenVulns = (cdx) => {
        const vulns = [];
        for (const v of (cdx.vulnerabilities || [])) {
            for (const affect of (v.affects || [])) {
                vulns.push({ purl: affect.ref, osv_id: v.id, severity: v.ratings?.[0]?.severity ?? null });
            }
        }
        return vulns;
    };

    const { introduced, resolved } = diffVulns(flattenVulns(oldCdx), flattenVulns(newCdx));

    return {
        summary: {
            ...compDiff.summary,
            newVulnerabilities:      introduced.length,
            resolvedVulnerabilities: resolved.length,
        },
        added:    compDiff.added,
        removed:  compDiff.removed,
        updated:  compDiff.updated,
        newVulnerabilities:      introduced,
        resolvedVulnerabilities: resolved,
    };
}

module.exports = { diffComponents, diffVulns, diffCycloneDX };
