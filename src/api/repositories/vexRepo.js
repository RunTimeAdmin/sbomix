'use strict';

async function upsertStatement(db, orgId, componentId, osvId, status, justification, impactStatement) {
    const { rows } = await db.query(
        `INSERT INTO vex_statements
           (org_id, component_id, osv_id, status, justification, impact_statement, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,NOW())
         ON CONFLICT (org_id, component_id, osv_id) DO UPDATE
           SET status           = EXCLUDED.status,
               justification    = EXCLUDED.justification,
               impact_statement = EXCLUDED.impact_statement,
               updated_at       = NOW()
         RETURNING *`,
        [orgId, componentId, osvId, status, justification || null, impactStatement || null]
    );
    return rows[0];
}

async function listStatements(db, orgId, { osvId, componentId } = {}) {
    const conditions = ['vx.org_id = $1'];
    const params     = [orgId];
    if (osvId) {
        params.push(osvId);
        conditions.push(`vx.osv_id = $${params.length}`);
    }
    if (componentId) {
        params.push(componentId);
        conditions.push(`vx.component_id = $${params.length}`);
    }
    const { rows } = await db.query(
        `SELECT vx.id, vx.component_id, c.purl, c.name AS component_name, c.version,
                vx.osv_id, vx.status, vx.justification, vx.impact_statement,
                vx.created_at, vx.updated_at
         FROM vex_statements vx
         JOIN components c ON c.id = vx.component_id
         WHERE ${conditions.join(' AND ')}
         ORDER BY vx.updated_at DESC`,
        params
    );
    return rows;
}

async function deleteStatement(db, orgId, id) {
    const { rowCount } = await db.query(
        `DELETE FROM vex_statements WHERE id = $1 AND org_id = $2`,
        [id, orgId]
    );
    return rowCount > 0;
}

module.exports = { upsertStatement, listStatements, deleteStatement };
