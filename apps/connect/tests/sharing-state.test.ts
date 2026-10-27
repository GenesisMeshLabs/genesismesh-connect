import { test } from "node:test";
import assert from "node:assert/strict";
import { sharingChoices, sharingDevices } from "../src/sharing-state.ts";
import type { HomeStatus } from "../src/home-state.ts";
test("phone choices require real capabilities and an actual remote inbox", () => {
 const status = {can_share:true, can_share_folder:false, spaces:[], devices:[]} as unknown as HomeStatus;
 assert.deepEqual(sharingChoices(status).map(c=>c.kind), ["file","media","service","inbox"]);
 status.spaces=[{id:"in",host:"Phone",host_id:"p",name:"Inbox",kind:"inbox",own:false}];
 assert.ok(sharingChoices(status).some(c=>c.kind === "send"));
 status.spaces[0].own=true; assert.ok(!sharingChoices(status).some(c=>c.kind === "send"));
});
test("recipient identities are unique", () => {
 const d={id:"p",name:"Phone",selected:false,member:true,authority_connection:false};
 assert.equal(sharingDevices({devices:[d,d]} as HomeStatus).length,1);
});
