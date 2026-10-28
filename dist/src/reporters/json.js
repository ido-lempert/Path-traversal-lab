import fs from 'node:fs';
import path from 'node:path';
export function writeJson(report, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, 'report.json');
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  return file;
}
