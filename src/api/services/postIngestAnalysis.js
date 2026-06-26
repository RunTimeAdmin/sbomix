'use strict';

const db              = require('../db');
const { enrichWithOSV } = require('../../osv');

async function osvEnrichAsync(orgId, cdxComponents, purlToCompId) {
    const components = cdxComponents.map(c => ({
        name:      c.name,
        version:   c.version || 'unknown',
        purl:      c.purl,
        ecosystem: c.purl.split(':')[1]?.split('/')[0] ?? 'unknown',
    }));

    await enrichWithOSV(components, { timeout: 20000 });

    const vulnRows = [];
    for (const comp of components) {
        if (!comp.vulnerabilities?.length) continue;
        const compId = purlToCompId.get(comp.purl);
        if (!compId) continue;
        for (const v of comp.vulnerabilities) {
            vulnRows.push({
                compId,
                osvId:        v.id,
                cveId:        v.aliases?.find(a => a.startsWith('CVE-')) ?? null,
                severity:     v.severity === 'UNKNOWN' ? null : v.severity,
                cvssScore:    (v.cvss && !isNaN(parseFloat(v.cvss))) ? parseFloat(v.cvss) : null,
                fixedVersion: v.fixedIn?.[0] ?? null,
                title:        v.summary || null,
            });
        }
    }

    if (vulnRows.length) {
        await db.query(
            `INSERT INTO vulnerabilities
               (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             SELECT t.comp_id, $1, t.osv_id, t.cve_id, t.severity, t.cvss_score, t.fixed_version, t.title
             FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::numeric[], $7::text[], $8::text[])
                  AS t(comp_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             ON CONFLICT (component_id, osv_id) DO UPDATE
               SET severity      = EXCLUDED.severity,
                   cvss_score    = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
                   fixed_version = COALESCE(EXCLUDED.fixed_version, vulnerabilities.fixed_version),
                   last_checked  = NOW()`,
            [orgId,
             vulnRows.map(r => r.compId),
             vulnRows.map(r => r.osvId),
             vulnRows.map(r => r.cveId),
             vulnRows.map(r => r.severity),
             vulnRows.map(r => r.cvssScore),
             vulnRows.map(r => r.fixedVersion),
             vulnRows.map(r => r.title)]
        );
    }
}

module.exports = { osvEnrichAsync };
