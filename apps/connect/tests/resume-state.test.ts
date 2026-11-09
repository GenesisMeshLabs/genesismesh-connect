import {test} from "node:test";
import assert from "node:assert/strict";
import {place,readPlace,resumeTo,RESUME_FOR_MS} from "../src/resume-state.ts";

const now=Date.parse("2026-11-09T12:00:00Z");

test("a remembered place comes back as it was",()=>{
  const saved=place("files","s1",["2025","receipts"],now);
  assert.deepEqual(readPlace(JSON.stringify(saved),now+60_000),saved);
  assert.deepEqual(place("devices",null,["ignored"],now).path,[],"No folder without a Space");
});

test("a missing, malformed, stale or unsafe place is ignored",()=>{
  const ok=place("files","s1",["a"],now);
  assert.equal(readPlace(null,now),null);
  assert.equal(readPlace("not json",now),null);
  assert.equal(readPlace(JSON.stringify({...ok,view:"admin"}),now),null);
  assert.equal(readPlace(JSON.stringify({...ok,path:"a/b"}),now),null);
  assert.equal(readPlace(JSON.stringify({...ok,path:[""]}),now),null);
  assert.equal(readPlace(JSON.stringify({...ok,path:Array(17).fill("x")}),now),null);
  assert.equal(readPlace(JSON.stringify({...ok,space:7}),now),null);
  assert.equal(readPlace(JSON.stringify(ok),now+RESUME_FOR_MS+1),null,"A day later Connect starts as usual");
  assert.equal(readPlace(JSON.stringify({...ok,at:now+3_600_000}),now),null,"Not from the future");
});

test("a Space no longer shared is not reopened, but the view is",()=>{
  const saved=place("files","gone",["a"],now);
  assert.deepEqual(resumeTo(saved,[{id:"s1"}]),{...saved,space:null,path:[]});
  const still=place("files","s1",["a"],now);
  assert.deepEqual(resumeTo(still,[{id:"s1"}]),still);
  assert.equal(resumeTo(null,[{id:"s1"}]),null);
});
