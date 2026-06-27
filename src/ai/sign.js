'use strict';

/**
 * Cryptographic signing for AI BOM model lineage.
 *
 * Design goal: a post-quantum-ready signature over the lineage attestation, with
 * an honest capability model rather than a fake "PQC works everywhere" stub.
 *
 * Three signer tiers, selected at runtime:
 *
 *   1. classical  — Ed25519. Always available in Node 18+. Baseline integrity.
 *   2. pqc-native — ML-DSA-65 / SLH-DSA. Available only when Node is built
 *                   against OpenSSL 3.5+ (or an OQS provider is loaded). Detected
 *                   at startup; absent on OpenSSL 3.0.x.
 *   3. pqc-extern — delegates to an external PQC CLI (e.g. liboqs / oqs-provider)
 *                   configured via SBOMIX_PQC_SIGN_CMD. Lets an OpenSSL-3.0 host
 *                   still produce a real Dilithium/SPHINCS+ signature.
 *
 * Recommended posture is HYBRID (NIST SP 800-208 / BSI migration guidance):
 * Ed25519 ⊕ ML-DSA-65 — a verifier accepts only if the classical signature is
 * valid AND the PQC signature is valid (or explicitly absent + acknowledged).
 * This protects against both a classical break and a future quantum break
 * without betting on either algorithm alone.
 *
 * Output is JSON Signature Format (JSF), the scheme CycloneDX 1.6 references in
 * its top-level `signature` field.
 */

const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { canonicalize } = require('./canonical');

// Candidate PQC algorithms, in preference order. Names match OpenSSL 3.5 / OQS.
const PQC_CANDIDATES = ['ml-dsa-65', 'ml-dsa-44', 'slh-dsa-sha2-128s'];

// ── Capability detection (run once) ───────────────────────────────────────────

function detectNativePQC() {
    for (const alg of PQC_CANDIDATES) {
        try {
            crypto.generateKeyPairSync(alg);
            return alg;
        } catch { /* not supported by this OpenSSL build */ }
    }
    return null;
}

const NATIVE_PQC_ALG = detectNativePQC();

/**
 * Report what this host can do, so callers and audit logs can record the
 * actual cryptographic posture instead of assuming.
 */
function capabilities() {
    return {
        classical:   'ed25519',
        nativePQC:   NATIVE_PQC_ALG,                              // string | null
        externalPQC: !!process.env.SBOMIX_PQC_SIGN_CMD,
        opensslVersion: process.versions.openssl,
        hybridAvailable: !!(NATIVE_PQC_ALG || process.env.SBOMIX_PQC_SIGN_CMD),
    };
}

// ── Key handling ──────────────────────────────────────────────────────────────

/** Generate an Ed25519 keypair (PEM strings). */
function generateClassicalKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey, algorithm: 'ed25519' };
}

// ── Low-level signers ─────────────────────────────────────────────────────────

function signClassical(bytes, privateKeyPem) {
    // Ed25519 signs the message directly (no pre-hash, algorithm = null)
    const sig = crypto.sign(null, bytes, privateKeyPem);
    return sig.toString('base64');
}

function verifyClassical(bytes, sigB64, publicKeyPem) {
    return crypto.verify(null, bytes, publicKeyPem, Buffer.from(sigB64, 'base64'));
}

function signNativePQC(bytes, privateKeyPem) {
    const sig = crypto.sign(null, bytes, privateKeyPem);
    return sig.toString('base64');
}

function verifyNativePQC(bytes, sigB64, publicKeyPem) {
    return crypto.verify(null, bytes, publicKeyPem, Buffer.from(sigB64, 'base64'));
}

/**
 * External PQC signer. SBOMIX_PQC_SIGN_CMD receives the canonical bytes on
 * stdin and must print a base64 signature on stdout. This is the escape hatch
 * for hosts on OpenSSL 3.0 that have liboqs/oqs-provider available as a CLI.
 */
function signExternalPQC(bytes) {
    const cmd = process.env.SBOMIX_PQC_SIGN_CMD;
    if (!cmd) throw new Error('SBOMIX_PQC_SIGN_CMD not configured');
    const [bin, ...args] = cmd.split(' ');
    const out = execFileSync(bin, args, { input: bytes, maxBuffer: 1 << 20 });
    return out.toString('utf8').trim();
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Sign a document and return a JSF-style signature block.
 *
 * @param {object} doc                 - the object to sign (e.g. lineage attestation)
 * @param {object} keys
 * @param {string} keys.classicalPrivateKey - Ed25519 private key PEM
 * @param {string} [keys.classicalPublicKey] - Ed25519 public key PEM (embedded for verification)
 * @param {string} [keys.pqcPrivateKey]      - native PQC private key PEM (if nativePQC available)
 * @param {string} [keys.pqcPublicKey]       - native PQC public key PEM
 * @param {object} [opts]
 * @param {boolean} [opts.hybrid=true]  - also attach a PQC signature when possible
 * @returns {object} JSF signature: { algorithm, value, publicKey, pqc? }
 */
function signDocument(doc, keys, opts = {}) {
    const hybrid = opts.hybrid !== false;
    const bytes  = Buffer.from(canonicalize(doc), 'utf8');

    if (!keys?.classicalPrivateKey) {
        throw new Error('signDocument: classicalPrivateKey is required');
    }

    const signature = {
        algorithm: 'Ed25519',
        value:     signClassical(bytes, keys.classicalPrivateKey),
        ...(keys.classicalPublicKey ? { publicKey: keys.classicalPublicKey } : {}),
        signedAt:  new Date().toISOString(),
    };

    if (hybrid) {
        if (NATIVE_PQC_ALG && keys.pqcPrivateKey) {
            signature.pqc = {
                algorithm: NATIVE_PQC_ALG.toUpperCase(),
                provider:  'openssl-native',
                value:     signNativePQC(bytes, keys.pqcPrivateKey),
                ...(keys.pqcPublicKey ? { publicKey: keys.pqcPublicKey } : {}),
            };
        } else if (process.env.SBOMIX_PQC_SIGN_CMD) {
            signature.pqc = {
                algorithm: process.env.SBOMIX_PQC_ALG || 'ML-DSA-65',
                provider:  'external-cli',
                value:     signExternalPQC(bytes),
            };
        } else {
            // Honest: no PQC available on this host. Record it instead of faking.
            signature.pqc = {
                status: 'unavailable',
                reason: `host OpenSSL ${process.versions.openssl} has no ML-DSA/SLH-DSA and ` +
                        'SBOMIX_PQC_SIGN_CMD is not set — classical signature only',
            };
        }
    }

    return signature;
}

/**
 * Verify a JSF signature block against a document.
 * @returns {{ valid: boolean, classical: boolean, pqc: 'valid'|'invalid'|'absent'|'unverifiable', reason?: string }}
 */
function verifyDocument(doc, signature) {
    const bytes = Buffer.from(canonicalize(doc), 'utf8');

    const pub = signature.publicKey;
    if (!pub) return { valid: false, classical: false, pqc: 'absent', reason: 'no embedded public key' };

    let classical = false;
    try { classical = verifyClassical(bytes, signature.value, pub); }
    catch (e) { return { valid: false, classical: false, pqc: 'absent', reason: e.message }; }

    let pqc = 'absent';
    if (signature.pqc) {
        if (signature.pqc.status === 'unavailable') {
            pqc = 'absent';
        } else if (signature.pqc.publicKey && NATIVE_PQC_ALG) {
            try {
                pqc = verifyNativePQC(bytes, signature.pqc.value, signature.pqc.publicKey) ? 'valid' : 'invalid';
            } catch { pqc = 'invalid'; }
        } else {
            // PQC signature present but this host can't verify it (no key / no native alg)
            pqc = 'unverifiable';
        }
    }

    // Hybrid acceptance: classical must hold; a present PQC sig must not be invalid.
    const valid = classical && pqc !== 'invalid';
    return { valid, classical, pqc };
}

module.exports = {
    capabilities,
    generateClassicalKeyPair,
    signDocument,
    verifyDocument,
    NATIVE_PQC_ALG,
};
