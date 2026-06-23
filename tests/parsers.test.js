'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parsePackageLock } = require('../src/parsers/npm');
const { parseCargoLock }   = require('../src/parsers/cargo');
const { parsePnpmLock }    = require('../src/parsers/pnpm');
const { parsePomXml }        = require('../src/parsers/maven');
const { parseGradleLock }    = require('../src/parsers/gradle');
const { parsePackagesLock }  = require('../src/parsers/dotnet');
const { detect }             = require('../src/parsers/detect');

const FIXTURES = path.join(__dirname, 'fixtures');

describe('npm parser', () => {
    test('parses package-lock.json v3 and returns all components', () => {
        const comps = parsePackageLock(path.join(FIXTURES, 'package-lock.json'));
        assert.ok(comps.length >= 5, `expected >=5 components, got ${comps.length}`);
    });

    test('all components have a valid purl', () => {
        const comps = parsePackageLock(path.join(FIXTURES, 'package-lock.json'));
        for (const c of comps) {
            assert.match(c.purl, /^pkg:npm\/.+@.+$/, `invalid purl: ${c.purl}`);
        }
    });

    test('dev packages get scope=dev', () => {
        const comps = parsePackageLock(path.join(FIXTURES, 'package-lock.json'));
        const jest = comps.find((c) => c.name === 'jest');
        assert.ok(jest, 'jest not found');
        assert.equal(jest.scope, 'dev');
    });

    test('transitive dependency captured (mime-types is transitive of accepts)', () => {
        const comps = parsePackageLock(path.join(FIXTURES, 'package-lock.json'));
        const mime = comps.find((c) => c.name === 'mime-types');
        assert.ok(mime, 'mime-types (transitive) not found — transitive dep missed');
    });

    test('dependency graph: express depends on accepts', () => {
        const comps = parsePackageLock(path.join(FIXTURES, 'package-lock.json'));
        const express = comps.find((c) => c.name === 'express');
        assert.ok(express, 'express not found');
        const hasAccepts = express.dependsOn.some((p) => p.includes('accepts'));
        assert.ok(hasAccepts, 'express.dependsOn should include accepts');
    });

    test('integrity hash parsed to SHA-512', () => {
        const comps = parsePackageLock(path.join(FIXTURES, 'package-lock.json'));
        const express = comps.find((c) => c.name === 'express');
        assert.ok(express.hashes.length > 0, 'no hashes on express');
        assert.equal(express.hashes[0].alg, 'SHA-512');
    });
});

describe('cargo parser', () => {
    test('parses Cargo.lock and returns all packages', () => {
        const comps = parseCargoLock(path.join(FIXTURES, 'Cargo.lock'));
        assert.ok(comps.length >= 4, `expected >=4 components, got ${comps.length}`);
    });

    test('all components have cargo purls', () => {
        const comps = parseCargoLock(path.join(FIXTURES, 'Cargo.lock'));
        for (const c of comps) {
            assert.match(c.purl, /^pkg:cargo\/.+@.+$/, `invalid purl: ${c.purl}`);
        }
    });

    test('checksums parsed as SHA-256 hashes', () => {
        const comps = parseCargoLock(path.join(FIXTURES, 'Cargo.lock'));
        const serde = comps.find((c) => c.name === 'serde');
        assert.ok(serde, 'serde not found');
        assert.ok(serde.hashes.length > 0, 'no hash on serde');
        assert.equal(serde.hashes[0].alg, 'SHA-256');
    });

    test('dependency graph: serde depends on serde_derive', () => {
        const comps = parseCargoLock(path.join(FIXTURES, 'Cargo.lock'));
        const serde = comps.find((c) => c.name === 'serde');
        assert.ok(serde.dependsOn.some((p) => p.includes('serde_derive')), 'missing serde -> serde_derive edge');
    });
});

describe('detector', () => {
    test('finds package-lock.json and Cargo.lock in fixtures', () => {
        const found = detect(FIXTURES, { recursive: false });
        const types = found.map((f) => f.type);
        assert.ok(types.includes('npm-lock'), 'package-lock.json not detected');
        assert.ok(types.includes('cargo-lock'), 'Cargo.lock not detected');
    });

    test('skips requirements.txt when poetry.lock present (same dir preference)', () => {
        const found = detect(FIXTURES, { recursive: false });
        const pypiFiles = found.filter((f) => f.ecosystem === 'pypi');
        const ecosystems = pypiFiles.map((f) => f.ecosystem);
        const unique = [...new Set(ecosystems)];
        assert.equal(ecosystems.length, unique.length, 'duplicate ecosystem entries returned');
    });

    test('detects pnpm-lock.yaml', () => {
        const found = detect(FIXTURES, { recursive: false });
        // pnpm-lock.yaml is in fixtures but package-lock.json is preferred
        // Both exist → package-lock.json wins. pnpm should not appear.
        const npmFiles = found.filter((f) => f.ecosystem === 'npm');
        assert.equal(npmFiles.length, 1, 'should return exactly one npm lock file');
        assert.equal(npmFiles[0].type, 'npm-lock', 'package-lock.json should win over pnpm-lock.yaml');
    });

    test('gradle.lockfile preferred over pom.xml in same directory', () => {
        // Both gradle.lockfile and pom.xml are in fixtures — gradle wins
        const found = detect(FIXTURES, { recursive: false });
        const javaFiles = found.filter((f) => f.ecosystem === 'maven');
        assert.equal(javaFiles.length, 1, 'should return exactly one java lock file');
        assert.equal(javaFiles[0].type, 'gradle-lock', 'gradle.lockfile should win over pom.xml');
    });

    test('detects packages.lock.json (.NET)', () => {
        const found = detect(FIXTURES, { recursive: false });
        const nuget = found.find((f) => f.type === 'nuget-lock');
        assert.ok(nuget, 'packages.lock.json should be detected');
    });
});

describe('pnpm parser', () => {
    test('parses pnpm-lock.yaml v6 and returns all packages', () => {
        const comps = parsePnpmLock(path.join(FIXTURES, 'pnpm-lock.yaml'));
        assert.ok(comps.length >= 4, `expected >=4 components, got ${comps.length}`);
    });

    test('all components have valid npm purls', () => {
        const comps = parsePnpmLock(path.join(FIXTURES, 'pnpm-lock.yaml'));
        for (const c of comps) {
            assert.match(c.purl, /^pkg:npm\/.+@.+$/, `invalid purl: ${c.purl}`);
        }
    });

    test('jest is marked as dev scope', () => {
        const comps = parsePnpmLock(path.join(FIXTURES, 'pnpm-lock.yaml'));
        const jest = comps.find((c) => c.name === 'jest');
        assert.ok(jest, 'jest not found');
        assert.equal(jest.scope, 'dev');
    });

    test('transitive dep captured (mime-types via accepts)', () => {
        const comps = parsePnpmLock(path.join(FIXTURES, 'pnpm-lock.yaml'));
        const mime = comps.find((c) => c.name === 'mime-types');
        assert.ok(mime, 'mime-types (transitive) not found');
    });

    test('dependency graph: express depends on accepts', () => {
        const comps = parsePnpmLock(path.join(FIXTURES, 'pnpm-lock.yaml'));
        const express = comps.find((c) => c.name === 'express');
        assert.ok(express, 'express not found');
        assert.ok(express.dependsOn.some((p) => p.includes('accepts')),
            'express.dependsOn missing accepts');
    });

    test('integrity hash parsed to SHA-512', () => {
        const comps = parsePnpmLock(path.join(FIXTURES, 'pnpm-lock.yaml'));
        const express = comps.find((c) => c.name === 'express');
        assert.ok(express.hashes.length > 0, 'no hashes on express');
        assert.equal(express.hashes[0].alg, 'SHA-512');
    });
});

describe('maven parser', () => {
    test('parses pom.xml and returns direct dependencies', () => {
        const comps = parsePomXml(path.join(FIXTURES, 'pom.xml'));
        assert.ok(comps.length >= 4, `expected >=4 components, got ${comps.length}`);
    });

    test('all components have valid maven purls', () => {
        const comps = parsePomXml(path.join(FIXTURES, 'pom.xml'));
        for (const c of comps) {
            assert.match(c.purl, /^pkg:maven\/.+@.+$/, `invalid purl: ${c.purl}`);
        }
    });

    test('test-scoped deps marked as dev', () => {
        const comps = parsePomXml(path.join(FIXTURES, 'pom.xml'));
        const junit = comps.find((c) => c.name.includes('junit-jupiter'));
        assert.ok(junit, 'junit-jupiter not found');
        assert.equal(junit.scope, 'dev');
    });

    test('resolves ${property} version variables', () => {
        const comps = parsePomXml(path.join(FIXTURES, 'pom.xml'));
        const spring = comps.find((c) => c.name === 'org.springframework/spring-core');
        assert.ok(spring, 'spring-core not found');
        assert.equal(spring.version, '5.3.30', 'property ${spring.version} not resolved');
    });

    test('log4j-core is present with correct version', () => {
        const comps = parsePomXml(path.join(FIXTURES, 'pom.xml'));
        const log4j = comps.find((c) => c.name === 'org.apache.logging.log4j/log4j-core');
        assert.ok(log4j, 'log4j-core not found');
        assert.equal(log4j.version, '2.20.0');
    });
});

describe('gradle parser', () => {
    test('parses gradle.lockfile and returns all packages', () => {
        const comps = parseGradleLock(path.join(FIXTURES, 'gradle.lockfile'));
        assert.ok(comps.length >= 10, `expected >=10 components, got ${comps.length}`);
    });

    test('all components have valid maven purls', () => {
        const comps = parseGradleLock(path.join(FIXTURES, 'gradle.lockfile'));
        for (const c of comps) {
            assert.match(c.purl, /^pkg:maven\/.+@.+$/, `invalid purl: ${c.purl}`);
        }
    });

    test('test-only deps marked as dev', () => {
        const comps = parseGradleLock(path.join(FIXTURES, 'gradle.lockfile'));
        const junit = comps.find((c) => c.name.includes('junit/junit'));
        assert.ok(junit, 'junit not found');
        assert.equal(junit.scope, 'dev');
    });

    test('runtime deps marked as required', () => {
        const comps = parseGradleLock(path.join(FIXTURES, 'gradle.lockfile'));
        const jackson = comps.find((c) => c.name.includes('jackson-databind'));
        assert.ok(jackson, 'jackson-databind not found');
        assert.equal(jackson.scope, 'required');
    });

    test('skips comment and empty= lines', () => {
        const comps = parseGradleLock(path.join(FIXTURES, 'gradle.lockfile'));
        assert.ok(comps.every((c) => c.name && c.version), 'some components have missing name or version');
    });
});

describe('.NET parser', () => {
    test('parses packages.lock.json and returns all packages', () => {
        const comps = parsePackagesLock(path.join(FIXTURES, 'packages.lock.json'));
        assert.ok(comps.length >= 5, `expected >=5 components, got ${comps.length}`);
    });

    test('all components have valid nuget purls', () => {
        const comps = parsePackagesLock(path.join(FIXTURES, 'packages.lock.json'));
        for (const c of comps) {
            assert.match(c.purl, /^pkg:nuget\/.+@.+$/, `invalid purl: ${c.purl}`);
        }
    });

    test('deduplicates packages across multiple target frameworks', () => {
        const comps = parsePackagesLock(path.join(FIXTURES, 'packages.lock.json'));
        const purls = comps.map((c) => c.purl);
        const unique = new Set(purls);
        assert.equal(purls.length, unique.size, 'duplicate components returned');
    });

    test('dependency graph: Swashbuckle depends on Swagger sub-packages', () => {
        const comps = parsePackagesLock(path.join(FIXTURES, 'packages.lock.json'));
        const swashbuckle = comps.find((c) => c.name === 'Swashbuckle.AspNetCore');
        assert.ok(swashbuckle, 'Swashbuckle.AspNetCore not found');
        assert.ok(swashbuckle.dependsOn.some((p) => p.includes('Swagger')),
            'Swashbuckle should depend on Swagger sub-packages');
    });

    test('SHA-512 content hash stored', () => {
        const comps = parsePackagesLock(path.join(FIXTURES, 'packages.lock.json'));
        const newtonsoft = comps.find((c) => c.name === 'Newtonsoft.Json');
        assert.ok(newtonsoft, 'Newtonsoft.Json not found');
        assert.ok(newtonsoft.hashes.length > 0, 'no hash on Newtonsoft.Json');
        assert.equal(newtonsoft.hashes[0].alg, 'SHA-512');
    });
});
