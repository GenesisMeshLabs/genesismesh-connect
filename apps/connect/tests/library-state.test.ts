import { test } from "node:test";
import assert from "node:assert/strict";
import { visibleSpaces, sortedFiles } from "../src/library-state.ts";
import type { HomeSpace } from "../src/home-state.ts";
const spaces: HomeSpace[] = [
 {id:"a",name:"Photos",host:"Desktop",host_id:"pc",own:false,kind:"folder"},
 {id:"b",name:"Inbox",host:"Phone",host_id:"phone",own:true,kind:"inbox"},
 {id:"c",name:"Work",host:"Laptop",host_id:"laptop",own:false,kind:"folder"},
];
test("library filters intersect device, ownership, kind and search without altering source", () => {
 assert.deepEqual(visibleSpaces(spaces," desktop ","remote","pc").map(s=>s.id),["a"]);
 assert.equal(visibleSpaces(spaces,"","mine","pc").length,0);
 assert.deepEqual(visibleSpaces(spaces,"","inbox","").map(s=>s.id),["b"]);
 assert.deepEqual(spaces.map(s=>s.id),["a","b","c"]);
});
test("folders remain first while files sort by size without changing pagination data", () => {
 const files=[{name:"a",kind:"file" as const,bytes:1,version:"1"},{name:"b",kind:"file" as const,bytes:50,version:"2"},{name:"z",kind:"folder" as const,bytes:0,version:"3"}];
 assert.deepEqual(sortedFiles(files,"size").map(f=>f.name),["z","b","a"]);
 assert.deepEqual(files.map(f=>f.name),["a","b","z"]);
});
