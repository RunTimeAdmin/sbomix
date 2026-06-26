'use strict';

/**
 * Deterministic canonicalization + hashing for AI BOM signing.
 *
 * Implements RFC 8785 (JSON Canonicalization Scheme, JCS) closely enough for
 * signature stability: object keys sorted lexicographically by UTF-16 code unit,
 * no insignificant whitespace, arrays preserved in order. The exact same bytes
 * are produced on every machine, which is the prerequisite for a verifiable
 * signature over a JSON document.
 */

const crypto = require('crypto');

/**
 * Produce the RFC 8785 canonical JSON string for a value.
 * Throws on non-finite numbers (JCS forbids NaN / Infinity).
 */
function canonicalize(value) {
    return serialize(value);
}

function serialize(v) {
    if (v === null) return 'null';

    const t = typeof v;
    if (t === 'number') {
        if (!Number.isFinite(v)) throw new Error('canonicalize: non-finite number is not permitted');
        return JSON.stringify(v);
    }
    if (t === 'boolean') return v ? 'true' : 'false';
    if (t === 'string')  return JSON.stringify(v);
    if (t === 'undefined') return undefined; // dropped from objects/arrays

    if (Array.isArray(v)) {
        const items = v.map((x) => {
            const s = serialize(x);
            return s === undefined ? 'null' : s;   // JSON arrays cannot hold holes
        });
        return `[${items.join(',')}]`;
    }

    if (t === 'object') {
        const keys = Object.keys(v).sort();        // lexicographic by code unit
        const parts = [];
        for (const k of keys) {
            const s = serialize(v[k]);
            if (s === undefined) continue;          // skip undefined-valued keys
            parts.push(`${JSON.stringify(k)}:${s}`);
        }
        return `{${parts.join(',')}}`;
    }

    throw new Error(`canonicalize: unsupported type ${t}`);
}

/** SHA-256 of the canonical form, returned as lowercase hex. */
function canonicalHash(value, encoding = 'hex') {
    return crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest(encoding);
}

/** SHA-256 of a buffer/string, lowercase hex. */
function sha256(data, encoding = 'hex') {
    return crypto.createHash('sha256').update(data).digest(encoding);
}

module.exports = { canonicalize, canonicalHash, sha256 };
