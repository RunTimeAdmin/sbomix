'use strict';

// SPDX license identifier → risk tier.
// forbidden  : strong copyleft — using in proprietary software requires disclosing source
// restricted : weak copyleft  — modifications to the library itself may require disclosure
// notice     : permissive with attribution / notice requirement
// permissive : effectively unrestricted for commercial use
const LICENSE_TIERS = new Map([
    // Forbidden
    ['AGPL-3.0',                          'forbidden'],
    ['AGPL-3.0-only',                     'forbidden'],
    ['AGPL-3.0-or-later',                 'forbidden'],
    ['GPL-2.0',                           'forbidden'],
    ['GPL-2.0-only',                      'forbidden'],
    ['GPL-2.0-or-later',                  'forbidden'],
    ['GPL-3.0',                           'forbidden'],
    ['GPL-3.0-only',                      'forbidden'],
    ['GPL-3.0-or-later',                  'forbidden'],
    ['OSL-3.0',                           'forbidden'],
    ['EUPL-1.1',                          'forbidden'],
    ['EUPL-1.2',                          'forbidden'],
    // Restricted
    ['LGPL-2.0',                          'restricted'],
    ['LGPL-2.0-only',                     'restricted'],
    ['LGPL-2.0-or-later',                 'restricted'],
    ['LGPL-2.1',                          'restricted'],
    ['LGPL-2.1-only',                     'restricted'],
    ['LGPL-2.1-or-later',                 'restricted'],
    ['LGPL-3.0',                          'restricted'],
    ['LGPL-3.0-only',                     'restricted'],
    ['LGPL-3.0-or-later',                 'restricted'],
    ['MPL-2.0',                           'restricted'],
    ['CDDL-1.0',                          'restricted'],
    ['CDDL-1.1',                          'restricted'],
    ['EPL-1.0',                           'restricted'],
    ['EPL-2.0',                           'restricted'],
    // Notice
    ['MIT',                               'notice'],
    ['Apache-2.0',                        'notice'],
    ['BSD-2-Clause',                      'notice'],
    ['BSD-3-Clause',                      'notice'],
    ['BSD-4-Clause',                      'notice'],
    ['ISC',                               'notice'],
    ['Artistic-2.0',                      'notice'],
    ['Zlib',                              'notice'],
    ['Python-2.0',                        'notice'],
    ['PSF-2.0',                           'notice'],
    ['Ruby',                              'notice'],
    ['PHP-3.0',                           'notice'],
    ['PHP-3.01',                          'notice'],
    // Permissive
    ['MIT-0',                             'permissive'],
    ['0BSD',                              'permissive'],
    ['Unlicense',                         'permissive'],
    ['CC0-1.0',                           'permissive'],
    ['WTFPL',                             'permissive'],
    ['blessing',                          'permissive'],
]);

/**
 * Resolve SPDX tier for a raw license string coming from the component model.
 * Handles plain strings ("MIT"), CycloneDX expressions ("MIT AND Apache-2.0"),
 * and the NOASSERTION sentinel.
 */
function tierFor(raw) {
    if (!raw || raw === 'NOASSERTION' || raw === 'UNKNOWN') return 'unknown';
    const id = raw.trim();
    // Direct hit
    if (LICENSE_TIERS.has(id)) return LICENSE_TIERS.get(id);
    // Expression like "MIT AND Apache-2.0" — take the worst tier
    if (id.includes(' AND ') || id.includes(' OR ')) {
        const parts = id.split(/\s+(?:AND|OR)\s+/);
        const tiers = parts.map(p => LICENSE_TIERS.get(p.trim()) ?? 'unknown');
        const order = ['forbidden', 'restricted', 'notice', 'permissive', 'unknown'];
        return order.find(t => tiers.includes(t)) ?? 'unknown';
    }
    return 'unknown';
}

/**
 * Extract the SPDX ID string from a pipeline component's licenses field.
 * Components store licenses as CycloneDX objects: [{ license: { id, name } }]
 * or as plain strings depending on the parser.
 */
function extractLicenseId(comp) {
    const raw = comp.licenses?.[0];
    if (!raw) return null;
    if (typeof raw === 'string') return raw;
    return raw.license?.id ?? raw.license?.name ?? null;
}

/**
 * Assess license compliance across all components.
 *
 * @param {object[]} components - normalized pipeline component objects
 * @returns {{ forbidden, restricted, unknown, score }}
 */
function assessLicenses(components) {
    const forbidden  = [];
    const restricted = [];
    const unknown    = [];

    for (const comp of components) {
        const id   = extractLicenseId(comp);
        const tier = tierFor(id ?? '');
        const entry = {
            name:    comp.name,
            version: comp.version,
            purl:    comp.purl,
            license: id || 'NOASSERTION',
        };
        if (tier === 'forbidden')        forbidden.push(entry);
        else if (tier === 'restricted')  restricted.push(entry);
        else if (tier === 'unknown')     unknown.push(entry);
    }

    // Penalty: 10 per forbidden, 2 per restricted, 1 per unknown (cap unknown at 20)
    const score = Math.max(0,
        100
        - forbidden.length  * 10
        - restricted.length *  2
        - Math.min(unknown.length, 20) * 1
    );

    return { forbidden, restricted, unknown, score };
}

module.exports = { assessLicenses, tierFor, extractLicenseId, LICENSE_TIERS };
