/** Reviewed public-surface inventory. This module never starts an authority. */
import { createHash } from 'node:crypto';
import { readFile, writeFile, access, realpath } from 'node:fs/promises';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const fail = (message) => { throw new Error(message); };
const requireValue = (condition, message) => { if (!condition) fail(message); };
const statuses = new Set(['verified', 'implemented-unverified', 'partial', 'planned', 'diagnostic-only', 'out-of-scope']);
const sourceKinds = [
  ['cli_commands', 'command', 'cli'], ['python', 'symbol', 'python'], ['signed_artifacts', 'model', 'artifact'],
];

export function publicEntries(core) {
  requireValue(core.contract_version === 1, 'Unreviewed upstream contract format.');
  const expected = ['contract_version','describes','http_routes','cli_commands','python','signed_artifacts','error_codes','packages','rules'].sort();
  requireValue(canonical(Object.keys(core).sort()) === canonical(expected), 'Upstream sections changed; review the new surface explicitly.');
  const entries = [];
  for (const route of core.http_routes) {
    if (route.level === 'internal') continue;
    requireValue(['stable','beta'].includes(route.level), `Unclassified HTTP stability: ${route.path}`);
    for (const method of route.methods)
      entries.push({id:`http:${method} ${route.path}`, kind:'http', level:route.level, declaration:route});
  }
  for (const [section, field, kind] of sourceKinds)
    for (const item of core[section]) {
      requireValue(['stable','beta'].includes(item.level), `Unclassified ${kind} stability: ${item[field]}`);
      entries.push({id:`${kind}:${item[field]}`, kind, level:item.level, declaration:item});
    }
  const ids = entries.map((entry) => entry.id);
  requireValue(new Set(ids).size === ids.length, 'Duplicate upstream operation/artifact ID.');
  return entries.sort((a,b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

export function compareContracts(reviewed, candidate) {
  const before = new Map(publicEntries(reviewed).map((entry) => [entry.id, canonical(entry.declaration)]));
  const after = new Map(publicEntries(candidate).map((entry) => [entry.id, canonical(entry.declaration)]));
  const added = [...after.keys()].filter((id) => !before.has(id));
  const removed = [...before.keys()].filter((id) => !after.has(id));
  const changed = [...before.keys()].filter((id) => after.has(id) && before.get(id) !== after.get(id));
  const referenceChanged = ['error_codes','packages','rules'].filter((key) => canonical(reviewed[key]) !== canonical(candidate[key]));
  // Internal routes are excluded from parity, but their changes still deserve review.
  if (canonical(reviewed.http_routes.filter((r) => r.level === 'internal')) !==
      canonical(candidate.http_routes.filter((r) => r.level === 'internal'))) referenceChanged.push('internal_routes');
  return {added, removed, changed, referenceChanged};
}

export function releasePins(requirements, cargo, lock) {
  const lines = requirements.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  requireValue(lines.length === 1 && /^genesis-mesh==\d+\.\d+\.\d+$/.test(lines[0]), 'Authority must have one exact release requirement.');
  const authority = lines[0].split('==')[1];
  const sdk = cargo.match(/^genesis-mesh-sdk\s*=\s*\{[^\n]*tag\s*=\s*"v(\d+\.\d+\.\d+)"[^\n]*\}/m)?.[1];
  requireValue(sdk === authority, 'Authority and SDK pins differ; qualify a supported release pair.');
  requireValue(/^genesis-mesh-sdk\s*=\s*\{[^\n]*git\s*=\s*"https:\/\/github.com\/GenesisMeshLabs\/sdk-rust"/m.test(cargo), 'SDK dependency must use the reviewed repository.');
  const block = lock.split('[[package]]').find((part) => /^\s*name = "genesis-mesh-sdk"\s*$/m.test(part));
  const locked = block?.match(/^version = "([^"]+)"/m)?.[1];
  const source = block?.match(/^source = "([^"]+)"/m)?.[1];
  requireValue(locked === sdk && source?.startsWith(`git+https://github.com/GenesisMeshLabs/sdk-rust?tag=v${sdk}#`) && /^[a-f0-9]{40}$/.test(source.split('#')[1] ?? ''), 'SDK Cargo.lock does not match the reviewed release pin.');
  return {authority, sdk, sdk_revision:source.split('#')[1]};
}

export function buildCoverage(core, mapping, source, pins) {
  requireValue(mapping.schema_version === 1 && source.schema_version === 1, 'Unsupported Connect inventory format.');
  requireValue(source.repository === 'GenesisMeshLabs/genesismesh' && source.file === 'contract/public-surface.json', 'Unexpected upstream contract origin.');
  requireValue(/^[a-f0-9]{40}$/.test(source.revision) && /^[a-f0-9]{64}$/.test(source.sha256), 'Immutable source revision and digest required.');
  requireValue(source.release === `v${pins.authority}`, 'Snapshot release differs from packaged authority pin; review the new upstream contract.');
  const sourceEntries = publicEntries(core);
  const expected = new Set(sourceEntries.map((entry) => entry.id));
  const assignments = new Map();
  const journeyIds = new Set();
  for (const journey of mapping.journeys) {
    requireValue(/^[a-z]+\.[a-z]+$/.test(journey.id) && !journeyIds.has(journey.id), `Invalid or duplicate journey ID: ${journey.id}`);
    journeyIds.add(journey.id);
    requireValue(statuses.has(journey.status) && ['partial','planned','verified'].includes(journey.manual) && ['partial','planned','verified'].includes(journey.assisted), `Invalid journey status: ${journey.id}`);
    requireValue(Number.isInteger(journey.phase) && journey.phase >= 0 && journey.phase <= 4, `Missing phase: ${journey.id}`);
    for (const name of ['outcome','screen','scope_note','approval','retry','recovery'])
      requireValue(typeof journey[name] === 'string' && journey[name].trim().length > 0, `Missing ${name}: ${journey.id}`);
    for (const name of ['prerequisites','actor_requirements','execution_locations'])
      requireValue(Array.isArray(journey[name]) && journey[name].length > 0, `Missing ${name}: ${journey.id}`);
    requireValue(['windows','macos','linux','ios','android'].every((platform) => statuses.has(journey.platforms?.[platform])), `Missing platform classification: ${journey.id}`);
    requireValue(journey.schemas && Object.hasOwn(journey.schemas,'input') && Object.hasOwn(journey.schemas,'output'), `Missing schema accounting: ${journey.id}`);
    requireValue(journey.evidence && ['sources','automated','physical'].every((kind) => Array.isArray(journey.evidence[kind])), `Missing evidence accounting: ${journey.id}`);
    if (journey.status === 'out-of-scope') requireValue(journey.exclusion_reason?.length > 20, `Out-of-scope reason required: ${journey.id}`);
    if (journey.status === 'verified' || journey.evidence.accepted === true || journey.manual === 'verified' || journey.assisted === 'verified') {
      requireValue(journey.status === 'verified' && journey.manual === 'verified' && journey.assisted === 'verified' && journey.evidence.accepted === true,
        `Verified outcome requires both manual and assisted acceptance: ${journey.id}`);
      requireValue(journey.schemas.input && journey.schemas.output && journey.evidence.automated.length && journey.evidence.physical.length && journey.acceptance_gaps.length === 0,
        `Verified claim lacks schemas, tests, physical evidence or closed gaps: ${journey.id}`);
    } else {
      requireValue(journey.evidence.accepted === false && journey.acceptance_gaps?.length > 0, `Incomplete journey must retain explicit acceptance gaps: ${journey.id}`);
    }
    for (const id of journey.operations) {
      requireValue(expected.has(id), `Removed or unknown mapped operation: ${id}`);
      requireValue(!assignments.has(id), `Operation is assigned twice: ${id}`);
      assignments.set(id, journey);
    }
  }
  const missing = sourceEntries.filter((entry) => !assignments.has(entry.id));
  requireValue(missing.length === 0, `Unmapped public capabilities:\n${missing.map((entry) => entry.id).join('\n')}`);
  for (const entry of sourceEntries)
    requireValue(mapping.reviewed_declarations?.[entry.id] === sha256(canonical(entry.declaration)),
      `Unreviewed declaration/schema change: ${entry.id}. Compare the upstream contract and review its mapping before regeneration.`);
  requireValue(Object.keys(mapping.reviewed_declarations).length === sourceEntries.length, 'Removed declarations remain in the reviewed signature inventory.');
  for (const key of ['error_codes','packages','rules'])
    requireValue(mapping.reviewed_references?.[key] === sha256(canonical(core[key])), `Unreviewed reference change: ${key}`);
  requireValue(mapping.reviewed_references?.internal_routes === sha256(canonical(core.http_routes.filter((r)=>r.level==='internal'))), 'Unreviewed internal route change.');
  const accepted = mapping.journeys.filter((journey) => journey.status === 'verified').length;
  return {
    schema_version:1, source, pins,
    accounting:{classified_public_entries:sourceEntries.length, user_outcomes:mapping.journeys.filter((j) => !['diagnostic-only','out-of-scope'].includes(j.status)).length,
      accepted_outcomes:accepted, internal_routes_excluded:core.http_routes.filter((r) => r.level === 'internal').length,
      full_parity:accepted > 0 && mapping.journeys.every((j) => ['verified','diagnostic-only','out-of-scope'].includes(j.status)),
      note:'Classification is not implementation, execution, usability acceptance or physical-device evidence. Counts overlap and are not a coverage percentage.'},
    journeys:mapping.journeys.map(({operations,...journey}) => ({...journey, public_entries:operations.length})),
    entries:sourceEntries.map((entry) => ({id:entry.id, kind:entry.kind, stability:entry.level,
      declaration_sha256:sha256(canonical(entry.declaration)), journey:assignments.get(entry.id).id,
      journey_status:assignments.get(entry.id).status,
      implementation:'Not asserted per operation by this inventory; see the journey scope and acceptance gaps.',
      schema_coverage:entry.kind === 'python' ? 'Declared Python call signature only; complete value schemas still required' : 'Complete input/output schemas are not supplied by this core inventory'})),
    references:{error_codes:{status:'planned',codes:core.error_codes,note:'Known vocabulary; not proof of guided handling for every error'},
      packages:core.packages,rules:core.rules,
      internal_routes:core.http_routes.filter((r) => r.level === 'internal')},
  };
}

export function renderReport(coverage) {
  const a=coverage.accounting;
  return `# Connect capability coverage\n\nGenerated by \`node scripts/connect-contract.mjs generate\`. Do not edit.\n\n`+
    `This is an inventory of **${a.classified_public_entries} classified public declarations** across **${coverage.journeys.length} journeys**, not ${a.classified_public_entries} implemented features. `+
    `**${a.accepted_outcomes} complete outcomes have recorded acceptance; full parity is not claimed.** Existing narrow workflows remain useful; complete manual/assisted outcomes have stricter acceptance gates.\n\n`+
    `The released upstream snapshot is [${coverage.source.release}](https://github.com/${coverage.source.repository}/blob/${coverage.source.revision}/${coverage.source.file}). `+
    `${a.internal_routes_excluded} internal routes are excluded from product parity. CLI/Python/artifact declarations overlap HTTP operations.\n\n`+
    `| Outcome | Phase | Manual | Assisted | Status | Public declarations |\n| --- | --- | --- | --- | --- | ---: |\n`+
    coverage.journeys.map((j)=>`| ${j.outcome} | ${j.phase} | ${j.manual} | ${j.assisted} | ${j.status} | ${j.public_entries} |`).join('\n')+
    `\n\nEvery journey retains prerequisites, actor requirements, platform status, retry/recovery boundaries, schema gaps and evidence accounting in [the reviewed mapping](../contract/connect-journeys.json). `+
    `All ${coverage.references.error_codes.codes.length} upstream error codes are inventoried; per-error guided recovery remains planned.\n\n`+
    `Current pins are checked against the snapshot and Cargo.lock. [Qualification](release-qualification.md) distinguishes passed tests from Windows policy blocks and unperformed native-device checks. `+
    `No runtime or assistant dispatch is enabled by this inventory.\n`;
}

async function readJson(path) { return JSON.parse(await readFile(path,'utf8')); }
async function validateFiles(mapping) {
  for (const j of mapping.journeys)
    for (const path of [...j.evidence.sources,...j.evidence.automated,...j.evidence.physical,j.schemas.input,j.schemas.output].filter(Boolean)) {
      requireValue(typeof path === 'string' && !path.includes('://') && !relative(ROOT,resolve(ROOT,path)).startsWith('..') && !/(^|[/\\])(temp|local|target|node_modules|\.env[^/\\]*)([/\\]|$)/.test(path), `Evidence/schema must be a public repository reference: ${path}`);
      await access(resolve(ROOT,path));
      requireValue(!relative(await realpath(ROOT),await realpath(resolve(ROOT,path))).startsWith('..'), `Evidence/schema resolves outside the repository: ${path}`);
    }
}
export async function loadCoverage() {
  const bytes = await readFile(resolve(ROOT,'contract/core-public-surface.json'));
  const source = await readJson(resolve(ROOT,'contract/core-source.json'));
  requireValue(sha256(bytes) === source.sha256, 'Upstream snapshot digest mismatch; review provenance before regeneration.');
  const mapping = await readJson(resolve(ROOT,'contract/connect-journeys.json'));
  await validateFiles(mapping);
  const pins = releasePins(await readFile(resolve(ROOT,'apps/connect/authority/core-requirements.txt'),'utf8'),
    await readFile(resolve(ROOT,'crates/connect-core/Cargo.toml'),'utf8'), await readFile(resolve(ROOT,'Cargo.lock'),'utf8'));
  const core = JSON.parse(bytes.toString('utf8'));
  return {coverage:buildCoverage(core,mapping,source,pins),core};
}
export async function verifyUpstream(source, request=fetch) {
  const url=`https://raw.githubusercontent.com/GenesisMeshLabs/genesismesh/${source.revision}/contract/public-surface.json`;
  const response=await request(url,{signal:AbortSignal.timeout(15000)});
  requireValue(response.ok,`Cannot verify immutable upstream snapshot: HTTP ${response.status}`);
  const bytes=Buffer.from(await response.arrayBuffer());
  requireValue(bytes.length <= 2*1024*1024 && sha256(bytes)===source.sha256,'Published immutable upstream snapshot differs from reviewed bytes.');
}
async function main() {
  const [command='check',upstream] = process.argv.slice(2);
  requireValue(['check','generate','compare','verify-upstream'].includes(command), 'Usage: connect-contract.mjs [check|generate|verify-upstream|compare <candidate public-surface.json>]');
  const {coverage,core}=await loadCoverage();
  if (command==='verify-upstream') {
    await verifyUpstream(coverage.source);
    console.log('Reviewed bytes match the published immutable core revision.'); return;
  }
  if (command==='compare') {
    requireValue(upstream,'Provide a candidate upstream contract file.');
    const changes=compareContracts(core,await readJson(resolve(upstream)));
    if (Object.values(changes).some((entries)=>entries.length)) fail(`Unreviewed upstream drift:\n${json(changes)}`);
    console.log('Candidate public contract matches the reviewed snapshot.'); return;
  }
  for (const [path,value] of [['contract/connect-coverage.json',json(coverage)],['docs/capability-coverage.md',renderReport(coverage)]]) {
    if (command==='generate') await writeFile(resolve(ROOT,path),value);
    else requireValue(await readFile(resolve(ROOT,path),'utf8')===value, `Stale generated inventory: ${path}. Review mappings then regenerate.`);
  }
  console.log(`${command}: ${coverage.accounting.classified_public_entries} public declarations classified; ${coverage.accounting.accepted_outcomes} complete accepted outcomes. No parity percentage claimed.`);
}
if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch((error)=>{console.error(error.message);process.exitCode=1;});
