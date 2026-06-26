'use strict';

async function executeIngestTx(client, orgId, appName, { version, commit, branch, cyclonedx, spdx, stats, aibom }) {
    const cdxComponents  = (cyclonedx.components || []).filter(c => c.purl);
    const cdxVulnCount   = (cyclonedx.vulnerabilities || []).length;
    const appRes = await client.query(
        `INSERT INTO applications (org_id, name)
         VALUES ($1, $2)
         ON CONFLICT (org_id, name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id`,
        [orgId, appName]
    );
    const appId = appRes.rows[0].id;

    const sbomRes = await client.query(
        `INSERT INTO sboms
           (app_id, org_id, version, commit_sha, branch, cyclonedx, spdx, aibom,
            component_count, vulnerability_count, critical_count,
            quality_score, ecosystems, elapsed_ms,
            ai_models, ai_threats, ai_critical, least_agency_score, generated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())
         RETURNING id`,
        [
            appId, orgId, version, commit, branch,
            cyclonedx, spdx || null, aibom ? JSON.stringify(aibom) : null,
            stats?.totalComponents ?? cdxComponents.length,
            stats?.vulnerabilities ?? cdxVulnCount,
            stats?.critical ?? 0,
            stats?.qualityScore ?? null,
            stats?.ecosystems ?? [],
            stats?.elapsedMs ?? null,
            stats?.aiModels    ?? 0,
            stats?.aiThreats   ?? 0,
            stats?.aiCritical  ?? 0,
            stats?.leastAgencyScore ?? null,
        ]
    );
    const sbomId = sbomRes.rows[0].id;

    await client.query(
        `INSERT INTO app_latest_sboms
           (app_id, org_id, sbom_id, created_at,
            component_count, vulnerability_count, critical_count, quality_score, ecosystems)
         VALUES ($1,$2,$3,NOW(),$4,$5,$6,$7,$8)
         ON CONFLICT (app_id) DO UPDATE
           SET sbom_id             = EXCLUDED.sbom_id,
               created_at          = EXCLUDED.created_at,
               component_count     = EXCLUDED.component_count,
               vulnerability_count = EXCLUDED.vulnerability_count,
               critical_count      = EXCLUDED.critical_count,
               quality_score       = EXCLUDED.quality_score,
               ecosystems          = EXCLUDED.ecosystems
         WHERE app_latest_sboms.created_at <= EXCLUDED.created_at`,
        [
            appId, orgId, sbomId,
            stats?.totalComponents ?? cdxComponents.length,
            stats?.vulnerabilities ?? cdxVulnCount,
            stats?.critical ?? 0,
            stats?.qualityScore ?? null,
            stats?.ecosystems ?? [],
        ]
    );

    const rootPurl    = cyclonedx.metadata?.component?.purl;
    const directPurls = new Set(
        cyclonedx.dependencies?.find(d => d.ref === rootPurl)?.dependsOn ?? []
    );

    const components = cyclonedx.components.filter(c => c.purl);
    if (!components.length) return { sbomId, purlToCompId: new Map(), appId };

    const purls      = components.map(c => c.purl);
    const names      = components.map(c => c.name);
    const versions   = components.map(c => c.version);
    const ecosystems = components.map(c => c.purl.split(':')[1]?.split('/')[0] ?? 'unknown');
    const licenses   = components.map(c =>
        c.licenses?.[0]?.license?.id || c.licenses?.[0]?.license?.name || null);

    const { rows: compRows } = await client.query(
        `INSERT INTO components (org_id, purl, name, version, ecosystem, license)
         SELECT $1, t.purl, t.name, t.version, t.ecosystem, t.license
         FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
              AS t(purl, name, version, ecosystem, license)
         ON CONFLICT (org_id, purl) DO UPDATE
           SET license = COALESCE(EXCLUDED.license, components.license)
         RETURNING purl, id`,
        [orgId, purls, names, versions, ecosystems, licenses]
    );

    const purlToCompId = new Map(compRows.map(r => [r.purl, r.id]));

    const linkRows = components
        .map(c => ({ id: purlToCompId.get(c.purl), scope: c.scope ?? 'required', direct: directPurls.has(c.purl) }))
        .filter(r => r.id);

    if (linkRows.length) {
        await client.query(
            `INSERT INTO sbom_components (sbom_id, component_id, scope, is_direct)
             SELECT $1, t.comp_id, t.scope, t.is_direct
             FROM UNNEST($2::uuid[], $3::text[], $4::boolean[])
                  AS t(comp_id, scope, is_direct)
             ON CONFLICT DO NOTHING`,
            [sbomId, linkRows.map(r => r.id), linkRows.map(r => r.scope), linkRows.map(r => r.direct)]
        );
    }

    const vulnRows = [];
    for (const v of (cyclonedx.vulnerabilities || [])) {
        const osvId  = v.id;
        const cveId  = v.advisories?.find(a => a.title?.startsWith('CVE-'))?.title
                    || (osvId?.startsWith('CVE-') ? osvId : null);
        const rating = v.ratings?.[0];
        for (const affected of (v.affects || [])) {
            const compId = purlToCompId.get(affected.ref);
            if (!compId) continue;
            vulnRows.push({
                compId, osvId, cveId,
                severity:  rating?.severity?.toUpperCase() ?? null,
                cvssScore: rating?.score ?? null,
                title:     v.description || null,
            });
        }
    }
    if (vulnRows.length) {
        await client.query(
            `INSERT INTO vulnerabilities
               (component_id, org_id, osv_id, cve_id, severity, cvss_score, fixed_version, title)
             SELECT t.comp_id, $1, t.osv_id, t.cve_id, t.severity, t.cvss_score, NULL, t.title
             FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::numeric[], $7::text[])
                  AS t(comp_id, osv_id, cve_id, severity, cvss_score, title)
             ON CONFLICT (component_id, osv_id) DO UPDATE
               SET severity     = EXCLUDED.severity,
                   cvss_score   = EXCLUDED.cvss_score,
                   last_checked = NOW()`,
            [orgId,
             vulnRows.map(r => r.compId), vulnRows.map(r => r.osvId),
             vulnRows.map(r => r.cveId),  vulnRows.map(r => r.severity),
             vulnRows.map(r => r.cvssScore), vulnRows.map(r => r.title)]
        );
    }

    return { sbomId, purlToCompId, appId };
}

module.exports = { executeIngestTx };
