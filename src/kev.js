'use strict';

const KEV_URL    = 'https://api.katzilla.dev/agents/security/actions/cisa-kev';
const REFRESH_MS = 24 * 60 * 60 * 1000;

// ── Standalone fetch (CLI) ────────────────────────────────────────────────────
// Returns a Set<cveId> or null if KATZILLA_API_KEY is not set.
async function fetchKEVSet() {
    const key = process.env.KATZILLA_API_KEY;
    if (!key) return null;

    const res = await fetch(KEV_URL, {
        method:  'POST',
        headers: { 'X-API-Key': key, 'Content-Type': 'application/json' },
        body:    '{}',
        signal:  AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`KEV fetch: HTTP ${res.status}`);
    const { data } = await res.json();
    return new Set(data.vulnerabilities.map(v => v.cveID));
}

// ── API-server side ───────────────────────────────────────────────────────────
// Lazy-require db so this module is safe to load in the CLI without pulling pg.
function db() { return require('./api/db'); }

async function refreshKEV() {
    const key = process.env.KATZILLA_API_KEY;
    if (!key) return;

    try {
        const res = await fetch(KEV_URL, {
            method:  'POST',
            headers: { 'X-API-Key': key, 'Content-Type': 'application/json' },
            body:    '{}',
            signal:  AbortSignal.timeout(30_000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const { data } = await res.json();
        const vulns = data?.vulnerabilities;
        if (!vulns?.length) throw new Error('empty response');

        await db().query(
            `INSERT INTO kev_catalog (cve_id, date_added, due_date, ransomware_use, refreshed_at)
             SELECT t.cve_id, t.date_added::date, t.due_date::date, t.ransomware_use, NOW()
             FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[])
                  AS t(cve_id, date_added, due_date, ransomware_use)
             ON CONFLICT (cve_id) DO UPDATE
               SET date_added     = EXCLUDED.date_added,
                   due_date       = EXCLUDED.due_date,
                   ransomware_use = EXCLUDED.ransomware_use,
                   refreshed_at   = NOW()`,
            [
                vulns.map(v => v.cveID),
                vulns.map(v => v.dateAdded),
                vulns.map(v => v.dueDate),
                vulns.map(v => v.knownRansomwareCampaignUse),
            ]
        );

        // Flag all matching vulnerabilities across all orgs
        await db().query(
            `UPDATE vulnerabilities v SET kev = TRUE
             FROM kev_catalog k
             WHERE (v.cve_id = k.cve_id OR v.osv_id = k.cve_id) AND v.kev = FALSE`
        );
        // Unflag any that were removed from the catalog (rare)
        await db().query(
            `UPDATE vulnerabilities v SET kev = FALSE
             WHERE v.kev = TRUE
               AND NOT EXISTS (
                 SELECT 1 FROM kev_catalog k
                 WHERE k.cve_id = v.cve_id OR k.cve_id = v.osv_id
               )`
        );

        console.log(`[kev] Synced ${vulns.length} entries`);
    } catch (err) {
        console.error('[kev] Refresh failed:', err.message);
    }
}

// Called after ingest/osv-enrich to immediately flag new vulns without waiting
// for the next 24h refresh cycle.
function applyKEVAfterIngest(orgId) {
    db().query(
        `UPDATE vulnerabilities v SET kev = TRUE
         FROM kev_catalog k
         WHERE v.org_id = $1
           AND (v.cve_id = k.cve_id OR v.osv_id = k.cve_id)
           AND v.kev = FALSE`,
        [orgId]
    ).catch(err => console.error('[kev:ingest]', err.message));
}

let _timer = null;
function startKEVRefresh() {
    refreshKEV();
    _timer = setInterval(refreshKEV, REFRESH_MS);
    if (_timer.unref) _timer.unref(); // don't block process exit
}

module.exports = { fetchKEVSet, startKEVRefresh, applyKEVAfterIngest };
