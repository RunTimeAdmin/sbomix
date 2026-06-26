'use strict';

async function findByEmail(db, email) {
    const { rows } = await db.query(
        `SELECT id, name FROM organizations WHERE email = $1`,
        [email]
    );
    return rows[0] || null;
}

async function getSettings(db, orgId) {
    const { rows } = await db.query(
        `SELECT vuln_alerts, plan, subscription_status, current_period_end
         FROM organizations WHERE id = $1`,
        [orgId]
    );
    return rows[0] || null;
}

async function updateVulnAlerts(db, orgId, enabled) {
    await db.query(
        `UPDATE organizations SET vuln_alerts = $1 WHERE id = $2`,
        [enabled, orgId]
    );
}

async function deleteOrg(db, orgId) {
    await db.query(`DELETE FROM organizations WHERE id = $1`, [orgId]);
}

async function createOrg(client, name, email, keyHash) {
    await client.query(
        `INSERT INTO organizations (name, email, api_key) VALUES ($1, $2, $3)`,
        [name, email, keyHash]
    );
}

async function findEmailVerification(db, token) {
    const { rows } = await db.query(
        `SELECT email, org_name FROM email_verifications WHERE token = $1 AND expires_at > NOW()`,
        [token]
    );
    return rows[0] || null;
}

async function deleteEmailVerification(db, token) {
    await db.query(`DELETE FROM email_verifications WHERE token = $1`, [token]);
}

async function upsertEmailVerification(db, email, orgName, token, expiresAt) {
    await db.query(
        `INSERT INTO email_verifications (email, org_name, token, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (email) DO UPDATE
           SET org_name   = EXCLUDED.org_name,
               token      = EXCLUDED.token,
               expires_at = EXCLUDED.expires_at,
               created_at = NOW()`,
        [email, orgName, token, expiresAt]
    );
}

module.exports = {
    findByEmail,
    getSettings,
    updateVulnAlerts,
    deleteOrg,
    createOrg,
    findEmailVerification,
    deleteEmailVerification,
    upsertEmailVerification,
};
