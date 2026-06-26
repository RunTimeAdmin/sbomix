'use strict';

async function createKey(db, orgId, name, keyHash, scopes) {
    const { rows } = await db.query(
        `INSERT INTO api_keys (org_id, name, key_hash, scopes)
         VALUES ($1, $2, $3, $4)
         RETURNING id, name, scopes, created_at`,
        [orgId, name, keyHash, scopes]
    );
    return rows[0];
}

async function listKeys(db, orgId) {
    const { rows } = await db.query(
        `SELECT id, name, scopes, created_at, last_used_at
         FROM api_keys
         WHERE org_id = $1 AND revoked_at IS NULL
         ORDER BY created_at`,
        [orgId]
    );
    return rows;
}

async function revokeKey(db, orgId, keyId) {
    const { rowCount } = await db.query(
        `UPDATE api_keys SET revoked_at = NOW()
         WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
        [keyId, orgId]
    );
    return rowCount > 0;
}

module.exports = { createKey, listKeys, revokeKey };
