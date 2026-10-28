import fs from 'node:fs';
import path from 'node:path';

// A Probe reads every fact from a single root directory.
// Fixture mode: root is a synthetic directory tree (demo/tests, no host access).
// Live mode: root is '/' and the tool inspects the container it runs inside.
export class Probe {
  constructor(root, { live = false } = {}) {
    this.root = root;
    this.live = live;
  }
  p(rel) { return path.join(this.root, rel); }
  exists(rel) { try { fs.lstatSync(this.p(rel)); return true; } catch { return false; } }
  read(rel) { try { return fs.readFileSync(this.p(rel), 'utf8'); } catch { return null; } }
  stat(rel) { try { return fs.lstatSync(this.p(rel)); } catch { return null; } }
  list(rel) { try { return fs.readdirSync(this.p(rel)); } catch { return []; } }
}

export function octalMode(stat) {
  return (stat.mode & 0o7777).toString(8).padStart(4, '0');
}

export function get(obj, dotted) {
  return dotted.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
