'use strict';

const fs   = require('fs');
const path = require('path');
const { XMLParser }     = require('fast-xml-parser');
const { spawnSync }     = require('child_process');
const { createComponent } = require('../component');

const PARSER = new XMLParser({ ignoreAttributes: false, isArray: (name) => name === 'dependency' });

/**
 * Parse a Maven pom.xml.
 *
 * Strategy:
 *  1. Always parse pom.xml for declared (direct) dependencies.
 *  2. If `mvn` is available, run `mvn dependency:list` for full transitive graph.
 *  3. If mvn is not available, warn and return direct deps only.
 */
function parsePomXml(filePath) {
    const xml  = fs.readFileSync(filePath, 'utf8');
    const doc  = PARSER.parse(xml);
    const proj = doc.project || {};

    // Resolve property variables like ${spring.version}
    const props = buildProperties(proj);

    const directDeps = parseDeclaredDeps(proj, props);

    // Attempt full transitive resolution via mvn if available
    const projectDir = path.dirname(filePath);
    const mvnResult  = tryMvnDependencyList(projectDir);

    if (mvnResult) {
        return mergeMvnOutput(mvnResult, directDeps);
    }

    if (directDeps.length > 0) {
        process.stderr.write(
            `[packrai] maven: mvn not found — returning ${directDeps.length} direct ` +
            `deps only. Install Maven for full transitive resolution.\n`
        );
    }

    return directDeps;
}

// ── Property resolution ────────────────────────────────────────────────────

function buildProperties(proj) {
    const props = {};

    // Parent version as fallback
    if (proj.parent?.version) props['project.parent.version'] = proj.parent.version;
    if (proj.version)         props['project.version']        = String(proj.version);
    if (proj.groupId)         props['project.groupId']        = proj.groupId;

    // <properties> block
    const raw = proj.properties || {};
    for (const [k, v] of Object.entries(raw)) {
        props[k] = String(v);
    }

    return props;
}

function resolveValue(val, props) {
    if (!val) return val;
    return String(val).replace(/\$\{([^}]+)\}/g, (_, key) => props[key] ?? `\${${key}}`);
}

// ── Parse <dependencies> section ─────────────────────────────────────────

function parseDeclaredDeps(proj, props) {
    const raw = proj.dependencies?.dependency || [];
    const mgmt = buildDependencyMgmt(proj, props);
    const components = [];

    for (const dep of raw) {
        const groupId    = resolveValue(dep.groupId,    props);
        const artifactId = resolveValue(dep.artifactId, props);
        let   version    = resolveValue(dep.version,    props);
        const scope      = (dep.scope || 'compile').toLowerCase();

        // Skip import-scope BOMs (they're not real runtime deps)
        if (scope === 'import') continue;

        // Fall back to dependencyManagement version
        if (!version || version.startsWith('${')) {
            const key = `${groupId}:${artifactId}`;
            version   = mgmt[key] || version;
        }

        if (!groupId || !artifactId || !version || version.startsWith('${')) continue;

        const isDev = scope === 'test' || scope === 'provided';

        components.push(createComponent({
            name:      `${groupId}/${artifactId}`,
            version,
            ecosystem: 'maven',
            hashes:    [],
            license:   null,
            scope:     isDev ? 'dev' : 'required',
        }));
    }

    return components;
}

function buildDependencyMgmt(proj, props) {
    const mgmt = {};
    const raw  = proj.dependencyManagement?.dependencies?.dependency || [];
    for (const dep of raw) {
        const g = resolveValue(dep.groupId,    props);
        const a = resolveValue(dep.artifactId, props);
        const v = resolveValue(dep.version,    props);
        if (g && a && v) mgmt[`${g}:${a}`] = v;
    }
    return mgmt;
}

// ── Optional: mvn dependency:list ────────────────────────────────────────

function tryMvnDependencyList(projectDir) {
    // Locate mvn on PATH (works on Windows + Unix)
    const mvnCmd = process.platform === 'win32' ? 'mvn.cmd' : 'mvn';

    const result = spawnSync(
        mvnCmd,
        ['-q', '-B', 'dependency:list', '-DoutputAbsoluteArtifactFilename=false',
         '-DincludeScope=runtime', '-f', 'pom.xml'],
        { cwd: projectDir, encoding: 'utf8', timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'] }
    );

    if (result.status !== 0 || result.error) return null;
    return result.stdout;
}

/**
 * Parse `mvn dependency:list` output and merge with known direct deps.
 *
 * Line format:
 *   [INFO]    groupId:artifactId:type:version:scope
 */
function mergeMvnOutput(stdout, directDeps) {
    const directPurls = new Set(directDeps.map(c => c.purl));
    const components  = [...directDeps];

    const pattern = /^\[INFO\]\s+([^:]+):([^:]+):[^:]+:([^:]+):(\w+)\s*$/;

    for (const line of stdout.split('\n')) {
        const m = line.match(pattern);
        if (!m) continue;

        const [, groupId, artifactId, version, scope] = m;
        const isdev = scope === 'test' || scope === 'provided';
        const comp  = createComponent({
            name:      `${groupId}/${artifactId}`,
            version,
            ecosystem: 'maven',
            hashes:    [],
            license:   null,
            scope:     isdev ? 'dev' : 'required',
        });

        if (directPurls.has(comp.purl)) continue;

        components.push(comp);
    }

    return components;
}

module.exports = { parsePomXml };
