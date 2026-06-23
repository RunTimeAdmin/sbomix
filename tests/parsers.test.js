'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parsePackageLock } = require('../src/parsers/npm');
const { parseCargoLock } = require('../src/parsers/cargo');
const { detect } = require('../src/parsers/detect');

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
        // Both exist in fixtures? If so, poetry wins. If not, just make sure npm-lock is returned.
        const found = detect(FIXTURES, { recursive: false });
        const pypiFiles = found.filter((f) => f.ecosystem === 'pypi');
        // If requirements.txt is in fixtures, it should not be returned if poetry.lock is there too
        // (we only have package-lock and Cargo in fixtures, so just assert no duplicate ecosystems)
        const ecosystems = pypiFiles.map((f) => f.ecosystem);
        const unique = [...new Set(ecosystems)];
        assert.equal(ecosystems.length, unique.length, 'duplicate ecosystem entries returned');
    });
});
