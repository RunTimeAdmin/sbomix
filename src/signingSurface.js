'use strict';

/**
 * Signing-surface detection for the crypto-agent report profile.
 *
 * Flags dependencies capable of holding or using private keys — wallet SDKs,
 * key-derivation libraries, and cloud KMS clients — plus local .env files
 * that reference key material by variable name.
 *
 * This is presence detection, not a code audit: a match means "this
 * deployment touches signing capability," not "this component is
 * compromised."
 *
 * Privacy: env scanning captures variable NAMES only. The regex never
 * captures a value group, so a value can't leak into the report even by
 * accident.
 */

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
    'node_modules', '.git', 'vendor', 'dist', 'build',
    '__pycache__', '.venv', 'venv', '.tox', 'target', '.cache',
]);

// Well-known packages that hold or use private keys / signing capability,
// grouped by chain/category. Not exhaustive — a defensible starting set per
// ecosystem, not an accusation list. Package presence, not package trust.
const SIGNING_PACKAGES = {
    npm: [
        { name: 'ethers', category: 'evm' },
        { name: 'web3', category: 'evm' },
        { name: 'viem', category: 'evm' },
        { name: '@ethersproject/wallet', category: 'evm' },
        { name: '@ethersproject/signing-key', category: 'evm' },
        { name: '@ethereumjs/tx', category: 'evm' },
        { name: 'ethereumjs-wallet', category: 'evm' },
        { name: 'eth-sig-util', category: 'evm' },
        { name: '@metamask/eth-sig-util', category: 'evm' },
        { name: 'ethereum-cryptography', category: 'evm' },
        { name: '@solana/web3.js', category: 'solana' },
        { name: '@solana/wallet-adapter-base', category: 'solana' },
        { name: '@coral-xyz/anchor', category: 'solana' },
        { name: 'bitcoinjs-lib', category: 'bitcoin' },
        { name: 'bip39', category: 'key-derivation' },
        { name: 'bip32', category: 'key-derivation' },
        { name: 'hdkey', category: 'key-derivation' },
        { name: 'tiny-secp256k1', category: 'key-derivation' },
        { name: 'secp256k1', category: 'key-derivation' },
        { name: 'tweetnacl', category: 'key-derivation' },
        { name: '@cosmjs/stargate', category: 'cosmos' },
        { name: '@cosmjs/proto-signing', category: 'cosmos' },
        { name: '@polkadot/api', category: 'polkadot' },
        { name: '@polkadot/keyring', category: 'polkadot' },
        { name: 'near-api-js', category: 'near' },
        { name: '@ledgerhq/hw-app-eth', category: 'hardware-wallet' },
        { name: '@trezor/connect', category: 'hardware-wallet' },
        { name: '@aws-sdk/client-kms', category: 'cloud-kms' },
        { name: '@google-cloud/kms', category: 'cloud-kms' },
    ],
    pypi: [
        { name: 'web3', category: 'evm' },
        { name: 'eth-account', category: 'evm' },
        { name: 'eth-keys', category: 'evm' },
        { name: 'eth-utils', category: 'evm' },
        { name: 'solana', category: 'solana' },
        { name: 'bitcoinlib', category: 'bitcoin' },
        { name: 'bit', category: 'bitcoin' },
        { name: 'mnemonic', category: 'key-derivation' },
        { name: 'hdwallet', category: 'key-derivation' },
        { name: 'coincurve', category: 'key-derivation' },
        { name: 'ecdsa', category: 'key-derivation' },
        { name: 'substrate-interface', category: 'polkadot' },
        { name: 'cosmpy', category: 'cosmos' },
        { name: 'algosdk', category: 'algorand' },
        { name: 'tronpy', category: 'tron' },
    ],
    cargo: [
        { name: 'solana-sdk', category: 'solana' },
        { name: 'solana-client', category: 'solana' },
        { name: 'anchor-lang', category: 'solana' },
        { name: 'ethers', category: 'evm' },
        { name: 'ethers-signers', category: 'evm' },
        { name: 'secp256k1', category: 'key-derivation' },
        { name: 'bitcoin', category: 'bitcoin' },
        { name: 'bip39', category: 'key-derivation' },
        { name: 'tiny-bip39', category: 'key-derivation' },
        { name: 'subxt', category: 'polkadot' },
        { name: 'cosmrs', category: 'cosmos' },
    ],
    golang: [
        { name: 'github.com/ethereum/go-ethereum', category: 'evm' },
        { name: 'github.com/gagliardetto/solana-go', category: 'solana' },
        { name: 'github.com/btcsuite/btcd', category: 'bitcoin' },
        { name: 'github.com/btcsuite/btcutil', category: 'bitcoin' },
        { name: 'github.com/tyler-smith/go-bip39', category: 'key-derivation' },
        { name: 'github.com/cosmos/cosmos-sdk', category: 'cosmos' },
        { name: 'github.com/centrifuge/go-substrate-rpc-client', category: 'polkadot' },
    ],
};

// Build a normalized lookup once at module load: "ecosystem:normalized-name" -> entry
const SIGNING_LOOKUP = new Map();
for (const [ecosystem, entries] of Object.entries(SIGNING_PACKAGES)) {
    for (const entry of entries) {
        SIGNING_LOOKUP.set(`${ecosystem}:${normalizeName(ecosystem, entry.name)}`, entry);
    }
}

function normalizeName(ecosystem, name) {
    if (ecosystem === 'pypi') return name.replace(/_/g, '-').toLowerCase();
    return name;
}

/**
 * Scan a project's components for signing/wallet library matches.
 * Direct vs transitive is derived the same way ingestService computes it:
 * from the CycloneDX root component's dependsOn list.
 *
 * @param {object[]} components  - pipeline components (post-generation)
 * @param {object} [cyclonedx]   - generated CycloneDX doc, used for direct/transitive
 * @returns {{ matches: object[], hasSigningSurface: boolean }}
 */
function scanSigningSurface(components, cyclonedx = null) {
    const rootPurl = cyclonedx?.metadata?.component?.purl;
    const directPurls = new Set(
        cyclonedx?.dependencies?.find((d) => d.ref === rootPurl)?.dependsOn ?? []
    );

    const matches = [];
    for (const comp of components) {
        const key = `${comp.ecosystem}:${normalizeName(comp.ecosystem, comp.name)}`;
        const entry = SIGNING_LOOKUP.get(key);
        if (!entry) continue;
        matches.push({
            name: comp.name,
            version: comp.version,
            ecosystem: comp.ecosystem,
            purl: comp.purl,
            category: entry.category,
            directness: directPurls.size > 0
                ? (directPurls.has(comp.purl) ? 'direct' : 'transitive')
                : 'unknown',
        });
    }

    return { matches, hasSigningSurface: matches.length > 0 };
}

// Env var name patterns commonly used for signing key material. Matched
// against variable NAMES only — the regex has no value capture group, so a
// secret value can never end up in a match result.
const KEY_ENV_NAME_RE = /^(PRIVATE_KEY|WALLET_(PRIVATE_)?KEY|SIGNER_KEY|SIGNING_KEY|MNEMONIC|SEED_PHRASE|HD_SEED|KMS_KEY_ID|[A-Z0-9_]*_PRIVATE_KEY|[A-Z0-9_]*_MNEMONIC)$/;

function walkForEnvFiles(root, maxDepth = 3) {
    const found = [];
    (function walk(dir, depth) {
        if (depth > maxDepth) return;
        let entries;
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
            const full = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (!SKIP_DIRS.has(e.name)) walk(full, depth + 1);
                continue;
            }
            if (e.name === '.env' || /^\.env\.[\w.-]+$/.test(e.name)) found.push(full);
        }
    })(root, 0);
    return found;
}

/**
 * Scan .env-style files under `root` for signing-key variable NAMES.
 * Never reads or reports values.
 *
 * @param {string} root
 * @returns {{ variable: string, sourceFile: string }[]}
 */
function scanEnvForSigningKeyNames(root) {
    const out = [];
    for (const fp of walkForEnvFiles(root)) {
        let lines;
        try { lines = fs.readFileSync(fp, 'utf8').split('\n'); } catch { continue; }
        for (const line of lines) {
            const eq = line.indexOf('=');
            if (eq < 1) continue;
            const varName = line.slice(0, eq).trim();
            if (KEY_ENV_NAME_RE.test(varName)) {
                out.push({ variable: varName, sourceFile: fp });
            }
        }
    }
    return out;
}

module.exports = { scanSigningSurface, scanEnvForSigningKeyNames, SIGNING_PACKAGES };
