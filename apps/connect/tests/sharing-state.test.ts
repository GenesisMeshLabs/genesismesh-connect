import { test } from "node:test";
import assert from "node:assert/strict";
import { sharingChoices, sharingDevices, receivingChoices } from "../src/sharing-state.ts";
import type { HomeStatus } from "../src/home-state.ts";
test("sending stays discoverable before another device enables receiving", () => {
 const status = {can_share:true, can_share_folder:false, spaces:[], devices:[]} as unknown as HomeStatus;
 assert.deepEqual(sharingChoices(status).map(c=>c.kind), ["file","media","service","inbox","send"]);
 status.spaces=[{id:"in",host:"Phone",host_id:"p",name:"Inbox",kind:"inbox",own:false}];
 assert.ok(sharingChoices(status).some(c=>c.kind === "send"));
 status.spaces[0].own=true; assert.ok(sharingChoices(status).some(c=>c.kind === "send"));
});
test("recipient identities are unique", () => {
 const d={id:"p",name:"Phone",selected:false,member:true,authority_connection:false};
 assert.equal(sharingDevices({devices:[d,d]} as HomeStatus).length,1);
});

test("receiving has a simple default and keeps an existing destination",()=>{
 const status={can_share_folder:true,spaces:[]} as unknown as HomeStatus;
 assert.deepEqual(receivingChoices(status).map(o=>o.value),["default","choose"]);
 status.spaces=[{id:"in",host:"This device",host_id:"me",name:"Inbox",kind:"inbox",own:true,destination:"Photos on this computer"}];
 assert.equal(receivingChoices(status)[0].value,"current");
 assert.match(receivingChoices(status)[0].label,/Photos/);
 status.can_share_folder=false;
 assert.deepEqual(receivingChoices(status),[{value:"current",label:"In Connect on this device"}]);
});
