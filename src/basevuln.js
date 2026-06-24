'use strict';

/**
 * Base image vulnerability lookup (Phase 2 — no Docker required).
 *
 * Strategy:
 *   1. Get an anonymous OAuth token from Docker Hub auth service
 *   2. Fetch the OCI image index (multi-platform manifest list)
 *   3. Locate the linux/amd64 SBOM attestation entry
 *   4. Pull the in-toto / SPDX blob from the attestation
 *   5. Extract OS packages + their purls
 *   6. Batch-query OSV for CVEs — same vuln object shape as osv.js
 *
 * Official Docker images (node, nginx, python, ubuntu, etc.) have SBOM
 * attestations built in since BuildKit 0.11. Private or older images will
 * return null gracefully and the pipeline skips base-image CVE data.
 */

const REGISTRY_AUTH = 'https://auth.docker.io/token';
const REGISTRY_API  = 'https://registry-1.docker.io/v2';
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const T             = 20_000; // per-request timeout ms

// OSV ecosystem names for PURL types found in Docker SBOM attestations
const PURL_TO_OSV = {
    apk:    'Alpine',
    deb:    'Debian',
    rpm:    'Red Hat',
    npm:    'npm',
    pypi:   'PyPI',
    gem:    'RubyGems',
    cargo:  'crates.io',
    golang: 'Go',
    maven:  'Maven',
    nuget:  'NuGet',
};

/**
 * Fetch CVEs for a base image using its SBOM attestation.
 *
 * @param {{ name: string, tag: string|null, digest: string|null }} img
 * @returns {Promise<object[]|null>}  vuln objects (same shape as osv.js) or null
 */
async function fetchBaseImageVulns(img) {
    try {
        const { namespace, repo } = parseImageName(img.name);
        const ref = img.digest || img.tag || 'latest';
        const token = await getToken(namespace, repo);
        const packages = await resolvePackages(token, namespace, repo, ref);
        if (!packages || packages.length === 0) return null;
        return await queryOSV(packages);
    } catch {
        return null; // best-effort — never fail the pipeline
    }
}

// ── Registry auth ─────────────────────────────────────────────────────────────

async function getToken(namespace, repo) {
    const scope = `repository:${namespace}/${repo}:pull`;
    const url = `${REGISTRY_AUTH}?service=registry.docker.io&scope=${encodeURIComponent(scope)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(T) });
    if (!res.ok) throw new Error(`registry auth HTTP ${res.status}`);
    const { token } = await res.json();
    if (!token) throw new Error('registry auth: no token in response');
    return token;
}

// ── Attestation resolution ────────────────────────────────────────────────────

async function resolvePackages(token, namespace, repo, ref) {
    // Step 1: get OCI image index (multi-platform manifest list)
    const indexRes = await fetch(
        `${REGISTRY_API}/${namespace}/${repo}/manifests/${encodeURIComponent(ref)}`,
        {
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: [
                    'application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json',
                ].join(', '),
            },
            signal: AbortSignal.timeout(T),
        }
    );
    if (!indexRes.ok) return null;

    const index = await indexRes.json();
    if (!Array.isArray(index.manifests)) return null;

    // Step 2: find SBOM attestation entry for linux/amd64
    const attDigest = findAttestationDigest(index.manifests);
    if (!attDigest) return null;

    // Step 3: pull attestation manifest
    const attRes = await fetch(
        `${REGISTRY_API}/${namespace}/${repo}/manifests/${attDigest}`,
        {
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/vnd.oci.image.manifest.v1+json',
            },
            signal: AbortSignal.timeout(T),
        }
    );
    if (!attRes.ok) return null;

    const attManifest = await attRes.json();
    const sbomLayer = findSBOMLayer(attManifest.layers || []);
    if (!sbomLayer) return null;

    // Step 4: pull SBOM blob (in-toto envelope with SPDX predicate)
    const blobRes = await fetch(
        `${REGISTRY_API}/${namespace}/${repo}/blobs/${sbomLayer.digest}`,
        {
            headers: { Authorization: `Bearer ${token}` },
            signal: AbortSignal.timeout(T),
        }
    );
    if (!blobRes.ok) return null;

    return parseSBOM(await blobRes.text());
}

function findAttestationDigest(manifests) {
    // Locate linux/amd64 image (must not itself be an attestation)
    const linux = manifests.find((m) =>
        m.platform?.os === 'linux' &&
        (m.platform?.architecture === 'amd64' || !m.platform?.architecture) &&
        !m.annotations?.['vnd.docker.reference.type'] &&
        !m.annotations?.['com.docker.reference.type']
    );
    if (!linux) return null;

    // Find attestation manifest that references the linux/amd64 digest
    const att = manifests.find((m) => {
        const type = m.annotations?.['vnd.docker.reference.type']
            || m.annotations?.['com.docker.reference.type'];
        const subject = m.annotations?.['vnd.docker.reference.digest']
            || m.annotations?.['com.docker.reference.digest'];
        return type === 'attestation-manifest' && subject === linux.digest;
    });
    return att?.digest ?? null;
}

function findSBOMLayer(layers) {
    // Prefer SPDX, then CycloneDX, then any in-toto layer as last resort
    return (
        layers.find((l) => l.annotations?.['in-toto.io/predicate-type'] === 'https://spdx.dev/Document') ||
        layers.find((l) => (l.annotations?.['in-toto.io/predicate-type'] ?? '').includes('cyclonedx')) ||
        layers.find((l) => (l.mediaType ?? '').includes('vnd.in-toto+json') &&
            !(l.annotations?.['in-toto.io/predicate-type'] ?? '').includes('slsa') &&
            !(l.annotations?.['in-toto.io/predicate-type'] ?? '').includes('provenance'))
    );
}

// ── SBOM parsing ──────────────────────────────────────────────────────────────

function parseSBOM(raw) {
    let doc;
    try {
        const parsed = JSON.parse(raw);
        if (parsed.payload) {
            // DSSE envelope: payload is base64-encoded in-toto statement
            const inner = JSON.parse(Buffer.from(parsed.payload, 'base64').toString('utf8'));
            doc = inner.predicate ?? inner;
        } else if (parsed.predicateType && parsed.predicate) {
            // Direct in-toto statement: { _type, predicateType, subject, predicate }
            doc = parsed.predicate;
        } else {
            // Plain SPDX or CycloneDX document
            doc = parsed;
        }
    } catch {
        return null;
    }

    if (doc.spdxVersion && Array.isArray(doc.packages)) {
        return extractSPDXPackages(doc);
    }
    if (doc.bomFormat === 'CycloneDX' && Array.isArray(doc.components)) {
        return extractCDXPackages(doc);
    }
    return null;
}

function extractSPDXPackages(doc) {
    const pkgs = [];
    for (const pkg of doc.packages) {
        if (!pkg.name || !pkg.versionInfo || pkg.versionInfo === 'NOASSERTION') continue;
        const purl = pkg.externalRefs?.find((r) => r.referenceType === 'purl')?.referenceLocator;
        const ecosystem = purl ? osvEcosystemFromPurl(purl) : null;
        if (ecosystem) pkgs.push({ name: pkg.name, version: pkg.versionInfo, ecosystem });
    }
    return pkgs;
}

function extractCDXPackages(doc) {
    const pkgs = [];
    for (const comp of doc.components) {
        if (!comp.name || !comp.version) continue;
        const ecosystem = comp.purl ? osvEcosystemFromPurl(comp.purl) : null;
        if (ecosystem) pkgs.push({ name: comp.name, version: comp.version, ecosystem });
    }
    return pkgs;
}

function osvEcosystemFromPurl(purl) {
    const m = purl.match(/^pkg:([^/@]+)/i);
    return m ? (PURL_TO_OSV[m[1].toLowerCase()] ?? null) : null;
}

// ── OSV query (same vuln object shape as src/osv.js) ─────────────────────────

async function queryOSV(packages) {
    const vulns = [];
    for (let i = 0; i < packages.length; i += 500) {
        const batch = packages.slice(i, i + 500);
        const queries = batch.map((p) => ({
            version: p.version,
            package: { name: p.name, ecosystem: p.ecosystem },
        }));
        try {
            const res = await fetch(OSV_BATCH_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ queries }),
                signal: AbortSignal.timeout(T),
            });
            if (!res.ok) continue;

            const { results } = await res.json();
            for (const result of (results ?? [])) {
                for (const v of (result.vulns ?? [])) {
                    vulns.push({
                        id:       v.id,
                        aliases:  v.aliases ?? [],
                        summary:  v.summary ?? '',
                        severity: extractSeverity(v),
                        cvss:     extractCVSS(v),
                        fixedIn:  extractFixes(v),
                        url:      `https://osv.dev/vulnerability/${v.id}`,
                    });
                }
            }
        } catch {
            continue;
        }
    }
    // Deduplicate by ID
    const seen = new Set();
    return vulns.filter((v) => !seen.has(v.id) && seen.add(v.id));
}

function extractSeverity(vuln) {
    const ratings = vuln.severity ?? [];
    const v3 = ratings.find((s) => s.type === 'CVSS_V3');
    const v2 = ratings.find((s) => s.type === 'CVSS_V2');
    const s = v3 ?? v2;
    if (!s) return vuln.database_specific?.severity?.toUpperCase() ?? 'UNKNOWN';
    const score = parseFloat(s.score);
    if (isNaN(score)) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

function extractCVSS(vuln) {
    const v3 = (vuln.severity ?? []).find((s) => s.type === 'CVSS_V3');
    return v3?.score ?? null;
}

function extractFixes(vuln) {
    const fixes = [];
    for (const affected of (vuln.affected ?? [])) {
        for (const range of (affected.ranges ?? [])) {
            for (const event of (range.events ?? [])) {
                if (event.fixed) fixes.push(event.fixed);
            }
        }
    }
    return [...new Set(fixes)];
}

// ── Image name parsing ────────────────────────────────────────────────────────

function parseImageName(name) {
    // Strip registry prefix — registry-1.docker.io, docker.io, index.docker.io
    const stripped = name.replace(/^(?:docker\.io|registry-1\.docker\.io|index\.docker\.io)\//, '');
    const parts = stripped.split('/');
    // Single-part name (e.g. "node") → official image under "library" namespace
    if (parts.length === 1) return { namespace: 'library', repo: parts[0] };
    return { namespace: parts.slice(0, -1).join('/'), repo: parts[parts.length - 1] };
}

module.exports = { fetchBaseImageVulns };
