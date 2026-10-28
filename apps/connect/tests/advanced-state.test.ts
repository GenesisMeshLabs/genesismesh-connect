import {test} from "node:test";
import assert from "node:assert/strict";
import {advancedGuidance,connectionFailure} from "../src/advanced-state.ts";
import type {HomeStatus} from "../src/home-state.ts";

const status={configured:true,disconnected:false,ready:false,problem:null,network:"Home",selected_device:"phone",
  devices:[{id:"phone",name:"My phone",selected:true,authority_connection:false,member:false}]} as HomeStatus;
test("help leads setup and disconnected devices back to the everyday controls",()=>{
  assert.equal(advancedGuidance({...status,configured:false}).view,"devices");
  const paused=advancedGuidance({...status,disconnected:true,ready:true});
  assert.equal(paused.view,"settings");assert.equal(paused.canCheck,false);
  const leaving=advancedGuidance({...status,leaving:true,configured:false});
  assert.match(leaving.action,/Finish leaving/);assert.equal(leaving.canCheck,false);
});
test("a saved device can be checked while not ready without claiming current access",()=>{
  assert.equal(advancedGuidance(status).canCheck,true);
  assert.equal(advancedGuidance({...status,selected_device:null}).canCheck,false);
  assert.equal(advancedGuidance({...status,devices:[]}).canCheck,false);
  assert.equal(advancedGuidance(null).canCheck,false);
});
test("network failures are distinct from refused identities and expired credentials",()=>{
  assert.match(connectionFailure("Connection timed out: deadline has elapsed").title,/reply in time/);
  assert.match(connectionFailure("Connection refused (os error 10061)").title,/open a connection/);
  assert.match(connectionFailure("HTTP connection refused (os error 61)").detail,/network computer/);
  assert.match(connectionFailure("certificate expired").title,/credential needs an update/);
  assert.match(connectionFailure("certificate revoked; request refused").title,/refused/);
  assert.match(connectionFailure("unexpected response").title,/could not be confirmed/);
});
