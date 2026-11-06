import {test,expect,type Page} from "@playwright/test";
async function open(page:Page,scenario:string) {
  await page.goto(`/tests/browser/host-admin.html?scenario=${scenario}`);
  await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-network")).toHaveText("Home network");
}
async function countCommits(page:Page) {
  return page.evaluate(()=>((window as unknown as {fixtureAdminCalls:string[]}).fixtureAdminCalls).filter(v=>v==="host_admin_commit").length);
}
type Control={holdNext(command:string):number;started(id:number):boolean;release(id:number):void;navigate():void;setNetwork(name:string):void;setDecision(value:"approved"|"revoked"):void};
async function hold(page:Page,command:string) {
  return page.evaluate(cmd=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.holdNext(cmd),command);
}
async function started(page:Page,id:number) {
  await expect.poll(()=>page.evaluate(id=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.started(id),id)).toBe(true);
}
async function release(page:Page,id:number) {await page.evaluate(id=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.release(id),id);}
async function closePresentation(page:Page,via:string) {
  if(via==="navigation")await page.evaluate(()=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.navigate());
  else if(via==="escape")await page.keyboard.press("Escape");
  else await page.getByRole("button",{name:"Close administrator settings"}).click();
  await expect(page.locator("#host-admin-dialog")).not.toBeVisible();
}
test("inspect actual review with user-presence gate; no privilege dispatch",async({page},testInfo)=>{
  await open(page,"locked");
  await expect(page.getByText("My phone",{exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Review request",exact:true}).click();
  expect(await page.locator("#host-admin-dialog").evaluate(el=>el.scrollTop)).toBe(0);
  await expect(page.locator("#host-admin-review-lines")).toContainText("Home network");
  await expect(page.locator("#host-admin-review-permissions")).toContainText("Approve new devices joining your network");
  await expect(page.locator("#host-admin-consequence")).toContainText("Individual resource policies still apply");
  await expect(page.locator("#host-admin-confirm")).toBeDisabled();
  await expect(page.locator("#host-admin-readiness")).toBeVisible();
  expect(await countCommits(page)).toBe(0);
  await page.screenshot({path:testInfo.outputPath("locked-review.png"),fullPage:true});
});
test("explicit opt-in and revocation use review then state confirmation in a fixture",async({page})=>{
  await open(page,"off");
  expect(await countCommits(page)).toBe(0);
  await page.getByRole("button",{name:"Review enabling Requests"}).click();
  await expect(page.locator("#host-admin-consequence")).toContainText("Each administrator still needs your approval");
  await page.locator("#host-admin-confirm").click();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("State confirmed");
  await expect(page.locator("#host-admin-enabled")).toBeVisible();
  await page.getByRole("button",{name:"Review request",exact:true}).click();
  await page.locator("#host-admin-confirm").click();
  await page.getByRole("button",{name:"Review revocation"}).click();
  await expect(page.locator("#host-admin-consequence")).toContainText("network membership");
  await page.locator("#host-admin-confirm").click();
  await expect(page.locator("#host-admin-outcome-text")).toContainText("permissions are revoked");
  expect(await countCommits(page)).toBe(3);
});
test("lost reply persists only a readback bookmark across reload and never resends",async({page},testInfo)=>{
  await open(page,"lost");await page.getByRole("button",{name:"Review request",exact:true}).click();
  await page.locator("#host-admin-confirm").click();
  await expect(page.locator("#host-admin-outcome-text")).toContainText("unconfirmed");
  expect(await countCommits(page)).toBe(1);
  await page.reload();await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-check")).toBeVisible();
  expect(await countCommits(page)).toBe(1);
  await page.getByRole("button",{name:"Check status",exact:true}).click();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("State confirmed");
  expect(await countCommits(page)).toBe(1);
  await page.screenshot({path:testInfo.outputPath("checked-lost-reply.png"),fullPage:true});
});
test("canceled authentication is refused; unknown members and expired reviews cannot approve",async({page})=>{
  await open(page,"cancel");await page.getByRole("button",{name:"Review request",exact:true}).click();await page.locator("#host-admin-confirm").click();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("Change refused");
  await expect(page.locator("#host-admin-outcome-detail")).toContainText("canceled");
  await page.goto("/tests/browser/host-admin.html?scenario=unknown");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.getByRole("button",{name:"Review request",exact:true})).toBeDisabled();
  await page.goto("/tests/browser/host-admin.html?scenario=expired");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await page.getByRole("button",{name:"Review request",exact:true}).click();
  await expect(page.locator("#host-admin-review-expired")).toBeVisible();await expect(page.locator("#host-admin-confirm")).toBeDisabled();
});
test("narrow layout keeps the review readable and device names remain text",async({page},testInfo)=>{
  await page.setViewportSize({width:390,height:844});await open(page,"unsafe-name");
  await expect(page.locator("#host-admin-pending h3")).toHaveText("Phone <img src=x onerror=alert(1)>");
  await expect(page.locator("#host-admin-pending img")).toHaveCount(0);
  await page.getByRole("button",{name:"Review request",exact:true}).click();
  const box=await page.locator("#host-admin-dialog").boundingBox();expect(box!.x).toBeGreaterThanOrEqual(0);expect(box!.width).toBeLessThanOrEqual(390);
  await expect(page.locator("#host-admin-confirm")).toBeDisabled();
  await page.screenshot({path:testInfo.outputPath("narrow-locked-review.png"),fullPage:true});
});

for(const via of ["button","escape","navigation"])test(`delayed abandoned review is fenced after ${via} close/reopen without clearing a newer load`,async({page})=>{
  await open(page,"locked");const oldReview=await hold(page,"host_admin_review");
  await page.getByRole("button",{name:"Review request",exact:true}).click();await started(page,oldReview);
  await closePresentation(page,via);
  const freshLoad=await hold(page,"host_admin_status");
  await page.getByRole("button",{name:"Manage administrators",exact:true}).click();await started(page,freshLoad);
  await release(page,oldReview);
  await expect(page.locator("#host-admin-review")).not.toBeVisible();
  await expect(page.locator("#host-admin-refresh")).toBeDisabled();
  await release(page,freshLoad);await expect(page.locator("#host-admin-network")).toHaveText("Home network");
  await expect(page.locator("#host-admin-refresh")).toBeEnabled();
  await expect(page.locator("#host-admin-review")).not.toBeVisible();expect(await countCommits(page)).toBe(0);
});
test("delayed status from a closed session cannot replace the reopened host view",async({page})=>{
  await page.goto("/tests/browser/host-admin.html?scenario=locked");const oldLoad=await hold(page,"host_admin_status");
  await page.getByRole("button",{name:"Manage administrators",exact:true}).click();await started(page,oldLoad);
  await closePresentation(page,"navigation");
  await page.evaluate(()=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.setNetwork("Fresh network"));
  await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-network")).toHaveText("Fresh network");
  await release(page,oldLoad);await expect(page.locator("#host-admin-network")).toHaveText("Fresh network");
});
test("delayed submitted confirmation survives a closed dialog and is not submitted again",async({page})=>{
  await open(page,"ready");await page.getByRole("button",{name:"Review request",exact:true}).click();
  const commit=await hold(page,"host_admin_commit");await page.locator("#host-admin-confirm").click();await started(page,commit);
  await closePresentation(page,"button");await release(page,commit);
  await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("State confirmed");
  await expect(page.locator("#host-admin-review")).not.toBeVisible();expect(await countCommits(page)).toBe(1);
});
test("delayed uncertain mutation and abandoned readback survive navigation without replay",async({page})=>{
  await open(page,"lost");await page.getByRole("button",{name:"Review request",exact:true}).click();
  const commit=await hold(page,"host_admin_commit");await page.locator("#host-admin-confirm").click();await started(page,commit);
  await closePresentation(page,"navigation");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-check")).toBeVisible();await release(page,commit);
  await expect(page.locator("#host-admin-outcome-text")).toContainText("unconfirmed");
  const check=await hold(page,"host_admin_check");await page.getByRole("button",{name:"Check status",exact:true}).click();await started(page,check);
  await closePresentation(page,"navigation");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-check")).toBeVisible();await release(page,check);
  await expect(page.locator("#host-admin-outcome-text")).toContainText("unconfirmed");
  expect(await page.evaluate(()=>localStorage.getItem("connect.host-admin.check.v1.fixture-host-scope"))).not.toBeNull();
  await page.getByRole("button",{name:"Check status",exact:true}).click();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("State confirmed");expect(await countCommits(page)).toBe(1);
});

test("a readback during delayed submission retains its bookmark and survives the older uncertain reply",async({page})=>{
  await open(page,"lost");await page.getByRole("button",{name:"Review request",exact:true}).click();
  const commit=await hold(page,"host_admin_commit");await page.locator("#host-admin-confirm").click();await started(page,commit);
  await closePresentation(page,"navigation");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await page.getByRole("button",{name:"Check status",exact:true}).click();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("State confirmed");
  expect(await page.evaluate(()=>localStorage.getItem("connect.host-admin.check.v1.fixture-host-scope"))).not.toBeNull();
  await expect(page.getByRole("button",{name:"Review revocation"})).toBeDisabled();
  await release(page,commit);
  await expect(page.locator("#host-admin-check")).not.toBeVisible();
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("State confirmed");
  expect(await page.evaluate(()=>localStorage.getItem("connect.host-admin.check.v1.fixture-host-scope"))).toBeNull();
  expect(await countCommits(page)).toBe(1);
});

test("an older Approved reply arriving first cannot suppress the newer Revoked readback",async({page})=>{
  await open(page,"ready");await page.getByRole("button",{name:"Review request",exact:true}).click();
  const commit=await hold(page,"host_admin_commit");await page.locator("#host-admin-confirm").click();await started(page,commit);
  await closePresentation(page,"navigation");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await page.evaluate(()=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.setDecision("revoked"));
  const check=await hold(page,"host_admin_check");await page.getByRole("button",{name:"Check status",exact:true}).click();await started(page,check);
  await release(page,commit);await release(page,check);
  await expect(page.locator("#host-admin-outcome-text")).toContainText("permissions are revoked");
  await expect(page.locator("#host-admin-outcome-title")).toHaveText("Current state checked");
  await expect(page.locator("#host-admin-check")).not.toBeVisible();
  expect(await countCommits(page)).toBe(1);
});

test("an unresolved newer readback keeps recovery after an older Approved reply and navigation/reload",async({page})=>{
  await open(page,"ready");await page.getByRole("button",{name:"Review request",exact:true}).click();
  const commit=await hold(page,"host_admin_commit");await page.locator("#host-admin-confirm").click();await started(page,commit);
  await closePresentation(page,"navigation");await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await page.evaluate(()=>(window as unknown as {fixtureAdminControl:Control}).fixtureAdminControl.setDecision("revoked"));
  const check=await hold(page,"host_admin_check");await page.getByRole("button",{name:"Check status",exact:true}).click();await started(page,check);
  await release(page,commit);
  expect(await page.evaluate(()=>localStorage.getItem("connect.host-admin.check.v1.fixture-host-scope"))).not.toBeNull();
  await closePresentation(page,"navigation");await release(page,check);
  await page.reload();await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.getByRole("button",{name:"Check status",exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Check status",exact:true}).click();
  await expect(page.locator("#host-admin-outcome-text")).toContainText("permissions are revoked");
  expect(await countCommits(page)).toBe(1);
});
