'use strict';

/**
 * HuggingFace model-card (README.md) parser.
 *
 * Extracts the human-authored governance text that CycloneDX modelCard
 * `considerations` expects — intended use, limitations, and ethical/bias notes —
 * directly from the model provider's own documentation. This is provider-stated
 * text, surfaced verbatim (trimmed), never synthesized: a static scan cannot
 * invent these, so they are only ever populated when the README actually says so.
 *
 * Pure and offline-testable: takes README text, returns structured considerations.
 */

const MAX_ITEMS      = 8;     // cap items per category
const MAX_ITEM_CHARS = 300;   // trim long bullets

// Section-header keyword → considerations bucket. Order matters: a "Bias, Risks
// and Limitations" header should classify as ethical (the bias signal), so the
// ethical bucket is tested before limitations.
const SECTION_MAP = [
    { bucket: 'useCases',     re: /\b(intended\s+uses?|use\s*cases?|direct\s+use|downstream\s+use|applications?)\b/i },
    { bucket: 'ethical',      re: /\b(bias(es)?|ethical|fairness|safety)\b/i },
    { bucket: 'limitations',  re: /\b(limitations?|out[-\s]?of[-\s]?scope|known\s+issues|risks?)\b/i },
];

/** Strip leading YAML frontmatter (--- ... ---) and return the markdown body. */
function stripFrontmatter(md) {
    const m = /^﻿?---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(md);
    return m ? md.slice(m[0].length) : md;
}

/** Split markdown into [{ title, body }] by ATX headers (#..####). */
function splitSections(md) {
    const lines = md.split(/\r?\n/);
    const sections = [];
    let cur = null;
    for (const line of lines) {
        const h = /^#{1,4}\s+(.+?)\s*#*\s*$/.exec(line);
        if (h) {
            if (cur) sections.push(cur);
            cur = { title: h[1].trim(), body: [] };
        } else if (cur) {
            cur.body.push(line);
        }
    }
    if (cur) sections.push(cur);
    return sections.map((s) => ({ title: s.title, body: s.body.join('\n').trim() }));
}

// Inline-markdown cleanup for a single extracted line.
function clean(text) {
    return text
        .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')  // links → text
        .replace(/[*_`>#]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, MAX_ITEM_CHARS);
}

// Pull bullet items from a section body; fall back to the first sentence(s).
function extractItems(body) {
    const bullets = [];
    for (const line of body.split(/\r?\n/)) {
        const b = /^\s*(?:[-*+]|\d+\.)\s+(.+)$/.exec(line);
        if (b) {
            const t = clean(b[1]);
            if (t) bullets.push(t);
        }
    }
    if (bullets.length) return bullets.slice(0, MAX_ITEMS);

    // No bullets — take the first non-empty paragraph, split into ≤2 sentences.
    const para = body.split(/\r?\n\r?\n/).map((p) => p.trim()).find(Boolean);
    if (!para) return [];
    const sentences = clean(para).split(/(?<=[.!?])\s+/).filter(Boolean);
    return sentences.slice(0, 2);
}

/**
 * Parse a model-card README into CycloneDX `considerations`.
 * @param {string} md - README.md contents
 * @returns {{ considerations: object }|null}
 */
function parseModelCardMarkdown(md) {
    if (!md || typeof md !== 'string') return null;
    const sections = splitSections(stripFrontmatter(md));

    const useCases = [];
    const limitations = [];
    const ethical = [];   // [{ name, mitigationStrategy }]

    for (const sec of sections) {
        const hit = SECTION_MAP.find((s) => s.re.test(sec.title));
        if (!hit) continue;
        const items = extractItems(sec.body);
        if (!items.length) continue;

        if (hit.bucket === 'useCases')     pushUnique(useCases, items);
        else if (hit.bucket === 'limitations') pushUnique(limitations, items);
        else if (hit.bucket === 'ethical') {
            // Each ethical/bias section → one consideration with the section as name
            ethical.push({ name: sec.title, mitigationStrategy: items.join(' ') });
        }
    }

    const considerations = {};
    if (useCases.length)    considerations.useCases = useCases.slice(0, MAX_ITEMS);
    if (limitations.length) considerations.technicalLimitations = limitations.slice(0, MAX_ITEMS);
    if (ethical.length)     considerations.ethicalConsiderations = ethical.slice(0, MAX_ITEMS);

    return Object.keys(considerations).length ? { considerations } : null;
}

/**
 * Derive CycloneDX quantitativeAnalysis.performanceMetrics from a HuggingFace
 * `model-index` block (frontmatter / cardData). Provider-reported, not invented.
 */
function metricsFromModelIndex(modelIndex) {
    if (!Array.isArray(modelIndex)) return null;
    const metrics = [];
    for (const entry of modelIndex) {
        for (const res of (entry.results || [])) {
            for (const m of (res.metrics || [])) {
                if (m.type && m.value !== undefined) {
                    metrics.push({
                        type: String(m.name || m.type),
                        value: String(m.value),
                        ...(typeof m.value === 'number' && m.value <= 1
                            ? { resolution: { type: 'normalized' } }
                            : {}),
                    });
                }
            }
        }
    }
    return metrics.length ? { performanceMetrics: metrics.slice(0, 20) } : null;
}

function pushUnique(arr, items) {
    for (const it of items) if (!arr.includes(it)) arr.push(it);
}

module.exports = { parseModelCardMarkdown, metricsFromModelIndex, stripFrontmatter, splitSections };
