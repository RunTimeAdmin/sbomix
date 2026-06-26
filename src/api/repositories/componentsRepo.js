'use strict';

async function verifyOwnership(db, orgId, componentId) {
    const { rows } = await db.query(
        `SELECT id FROM components WHERE id = $1 AND org_id = $2`,
        [componentId, orgId]
    );
    return rows.length > 0;
}

module.exports = { verifyOwnership };
