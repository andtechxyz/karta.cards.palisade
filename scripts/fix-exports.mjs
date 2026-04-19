#!/usr/bin/env node
// After `tsc -b`, rewrite workspace package exports from ./src/index.ts
// to ./dist/index.js so plain `node` (not tsx) can resolve them.
// Only runs inside the Docker build — dev uses tsx which handles .ts natively.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
for (const dir of readdirSync(join(root, 'packages'))) {
  const pkgPath = join(root, 'packages', dir, 'package.json');
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    let changed = false;
    if (pkg.exports?.['.'] === './src/index.ts') {
      pkg.exports['.'] = './dist/index.js';
      changed = true;
    }
    if (pkg.main === './src/index.ts') {
      pkg.main = './dist/index.js';
      changed = true;
    }
    if (pkg.types === './src/index.ts') {
      pkg.types = './dist/index.d.ts';
      changed = true;
    }
    if (changed) {
      writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
      console.log(`  fixed: packages/${dir}`);
    }
  } catch {
    // skip non-packages
  }
}
