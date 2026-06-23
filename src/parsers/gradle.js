'use strict';

const fs = require('fs');
const { createComponent } = require('../component');

/**
 * Parse gradle.lockfile (Gradle dependency locking).
 *
 * Enable in build.gradle with:
 *   dependencyLocking { lockAllConfigurations() }
 * Then generate with:
 *   ./gradlew dependencies --write-locks
 *
 * Format: group:artifact:version=config1,config2,...
 *   com.fasterxml.jackson.core:jackson-databind:2.15.3=compileClasspath,runtimeClasspath
 *   junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
 *   empty=
 */
function parseGradleLock(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    const components = [];

    for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed === 'empty=') continue;

        const eqIdx = trimmed.indexOf('=');
        if (eqIdx === -1) continue;

        const coords          = trimmed.slice(0, eqIdx);
        const configurations  = trimmed.slice(eqIdx + 1).split(',').map(s => s.trim()).filter(Boolean);

        const parts = coords.split(':');
        if (parts.length < 3) continue;

        const [groupId, artifactId, version] = parts;

        // Mark as dev if every configuration is test/annotation-processor only
        const isTestOnly = configurations.length > 0 && configurations.every(c => {
            const lc = c.toLowerCase();
            return lc.startsWith('test') || lc === 'annotationprocessor';
        });

        components.push(createComponent({
            name:      `${groupId}/${artifactId}`,
            version,
            ecosystem: 'maven',
            hashes:    [],
            license:   null,
            scope:     isTestOnly ? 'dev' : 'required',
        }));
    }

    return components;
}

module.exports = { parseGradleLock };
