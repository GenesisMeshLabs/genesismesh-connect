import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, cp, mkdir, mkdtemp, rm, realpath } from 'node:fs/promises';
import { resolve, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { ROOT, buildCoverage, compareContracts, loadCoverage, publicEntries, releasePins, renderReport, verifyUpstream } from '../connect-contract.mjs';

const {coverage,core}=await loadCoverage();
const mapping=JSON.parse(await readFile(resolve(ROOT,'contract/connect-journeys.json'),'utf8'));
const source=coverage.source;
const pins=coverage.pins;
const clone=(value)=>structuredClone(value);
const build=(c=core,m=mapping,s=source,p=pins)=>buildCoverage(c,m,s,p);

test('inventory classifies public HTTP methods and CLI/Python-only surface without claiming product parity',()=>{
  const built=build();
  assert.equal(built.entries.length,publicEntries(core).length);
  assert.ok(built.entries.some((entry)=>entry.id==='cli:trust oversight approve'));
  assert.ok(built.entries.some((entry)=>entry.id.startsWith('python:')));
  assert.ok(built.entries.some((entry)=>entry.id.startsWith('artifact:')));
  assert.equal(built.entries.some((entry)=>entry.id==='http:GET /'),false);
  assert.equal(built.accounting.accepted_outcomes,0);
  assert.equal(built.accounting.full_parity,false);
  assert.ok(renderReport(built).includes('not claimed'));
});
test('new public operation is a failing unreviewed capability, not automatically assigned by prefix',()=>{
  const candidate=clone(core);
  candidate.http_routes.push({methods:['POST'],path:'/admin/attestations/new-operation',level:'stable'});
  assert.throws(()=>build(candidate),/Unmapped public capabilities.*http:POST \/admin\/attestations\/new-operation/s);
});
test('removed operation cannot remain silently mapped',()=>{
  const candidate=clone(core);
  candidate.cli_commands=candidate.cli_commands.filter((entry)=>entry.command!=='trust oversight approve');
  assert.throws(()=>build(candidate),/Removed or unknown mapped operation: cli:trust oversight approve/);
});
test('declared Python signature and HTTP stability drift are reported',()=>{
  const candidate=clone(core);
  candidate.python[0].parameters.push({name:'new_required',kind:'keyword_only',required:true});
  const route=candidate.http_routes.find((entry)=>entry.level==='stable');
  route.level='beta';
  const drift=compareContracts(core,candidate);
  assert.ok(drift.changed.includes(`python:${candidate.python[0].symbol}`));
  assert.ok(drift.changed.includes(`http:${route.methods[0]} ${route.path}`));
  assert.throws(()=>build(candidate),/Unreviewed declaration\/schema change/);
});
test('unknown upstream sections, duplicate IDs and overlapping mappings fail',()=>{
  assert.throws(()=>build({...clone(core),new_public_surface:[]}),/Upstream sections changed/);
  const duplicate=clone(core); duplicate.python.push(duplicate.python[0]);
  assert.throws(()=>build(duplicate),/Duplicate upstream/);
  const overlap=clone(mapping); overlap.journeys[1].operations.push(overlap.journeys[0].operations[0]);
  assert.throws(()=>build(core,overlap),/assigned twice/);
});
test('changed error vocabulary, support declarations, rules and internal routes remain visible drift',()=>{
  const candidate=clone(core);
  candidate.error_codes.push('new_problem'); candidate.packages[0].support='Changed support';
  candidate.rules.error_envelope='Changed envelope';
  candidate.http_routes.find((route)=>route.level==='internal').path='/different-internal-path';
  assert.deepEqual(compareContracts(core,candidate).referenceChanged,['error_codes','packages','rules','internal_routes']);
  assert.throws(()=>build(candidate),/Unreviewed reference change/);
});
test('screen or test presence cannot upgrade a journey to verified',()=>{
  const claimed=clone(mapping); claimed.journeys[0].status='verified';
  assert.throws(()=>build(core,claimed),/both manual and assisted/);
  Object.assign(claimed.journeys[0],{manual:'verified',assisted:'verified'});
  claimed.journeys[0].evidence.accepted=true;
  assert.throws(()=>build(core,claimed),/lacks schemas, tests, physical evidence or closed gaps/);
});
test('incomplete and out-of-scope journeys require explicit gaps or reasons',()=>{
  const omitted=clone(mapping); omitted.journeys[0].acceptance_gaps=[];
  assert.throws(()=>build(core,omitted),/explicit acceptance gaps/);
  const excluded=clone(mapping); excluded.journeys[0].status='out-of-scope';
  assert.throws(()=>build(core,excluded),/Out-of-scope reason required/);
});
test('schema snapshot and pin mismatch require qualification before regeneration',()=>{
  assert.throws(()=>build(core,mapping,{...source,release:'v99.0.0'}),/Snapshot release differs/);
  const cargo='genesis-mesh-sdk = { git = "https://github.com/GenesisMeshLabs/sdk-rust", tag = "v2.3.4" }';
  const lock='[[package]]\nname = "genesis-mesh-sdk"\nversion = "2.3.4"\nsource = "git+https://github.com/GenesisMeshLabs/sdk-rust?tag=v2.3.4#'+ 'a'.repeat(40)+'"\n';
  assert.equal(releasePins('genesis-mesh==2.3.4\n',cargo,lock).authority,'2.3.4');
  assert.throws(()=>releasePins('genesis-mesh==2.3.5\n',cargo,lock),/pins differ/);
  assert.throws(()=>releasePins('genesis-mesh==2.3.4\n',cargo,lock.replace('version = "2.3.4"','version = "2.3.3"')),/Cargo.lock/);
  assert.throws(()=>releasePins('genesis-mesh>=2.3.4\n',cargo,lock),/exact release/);
});
test('immutable upstream validation refuses a changed body or failed fetch',async()=>{
  const bytes=await readFile(resolve(ROOT,'contract/core-public-surface.json'));
  await verifyUpstream(source,async(url)=>{
    assert.ok(url.includes(source.revision));
    return new Response(bytes);
  });
  await assert.rejects(verifyUpstream(source,async()=>new Response('{}')),/differs from reviewed bytes/);
  await assert.rejects(verifyUpstream(source,async()=>new Response('missing',{status:404})),/HTTP 404/);
});
test('CLI refuses stale output without repairing it, then explicitly regenerates deterministically',async()=>{
  const fixture=await mkdtemp(resolve(tmpdir(),'connect-contract-test-'));
  try {
    const paths=['scripts/connect-contract.mjs','contract','README.md','docs/everyday-workflow.md',
      'docs/server-node.md','docs/service-sharing.md','docs/capability-coverage.md','Cargo.lock',
      'crates/connect-core/Cargo.toml','apps/connect/authority/core-requirements.txt'];
    for (const path of paths) {
      await mkdir(dirname(resolve(fixture,path)),{recursive:true});
      await cp(resolve(ROOT,path),resolve(fixture,path),{recursive:true});
    }
    const run=(command)=>spawnSync(process.execPath,[resolve(fixture,'scripts/connect-contract.mjs'),command],{cwd:fixture,encoding:'utf8'});
    assert.equal(run('check').status,0);
    const artifact=resolve(fixture,'contract/connect-coverage.json');
    const expected=await readFile(artifact,'utf8');
    await writeFile(artifact,'{}\n');
    const refused=run('check');
    assert.equal(refused.status,1);
    assert.match(refused.stderr,/Stale generated inventory/);
    assert.equal(await readFile(artifact,'utf8'),'{}\n');
    assert.equal(run('generate').status,0);
    assert.equal(await readFile(artifact,'utf8'),expected);
    assert.equal(run('check').status,0);
    const sourcePath=resolve(fixture,'contract/core-public-surface.json');
    await writeFile(sourcePath,(await readFile(sourcePath,'utf8'))+' ');
    assert.match(run('generate').stderr,/digest mismatch/);
  } finally {
    // The recursive cleanup is restricted to this freshly created test directory.
    assert.equal(dirname(await realpath(fixture)),await realpath(tmpdir()));
    assert.ok(basename(fixture).startsWith('connect-contract-test-'));
    await rm(fixture,{recursive:true,force:true});
  }
});
