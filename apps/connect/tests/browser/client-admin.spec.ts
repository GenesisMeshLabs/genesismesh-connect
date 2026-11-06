import {test,expect,type Page} from "@playwright/test";
type Control={holdNext(command:string):number;started(id:number):boolean;release(id:number):void;navigate():void;changeContext(value:string):void;setResult(value:string):void;setCheckContext(value:string):void};
async function open(page:Page,scenario:string) {await page.goto(`/tests/browser/client-admin.html?scenario=${scenario}`);await page.getByRole("button",{name:"View joining permissions"}).click();await expect(page.locator("#client-admin-network")).toHaveText("Home network");}
async function hold(page:Page,command:string) {return page.evaluate(cmd=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.holdNext(cmd),command);}
async function started(page:Page,id:number){await expect.poll(()=>page.evaluate(id=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.started(id),id)).toBe(true);}
async function release(page:Page,id:number){await page.evaluate(id=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.release(id),id);}
async function readonly(page:Page){const calls=await page.evaluate(()=>(window as unknown as {fixtureClientCalls:string[]}).fixtureClientCalls);expect(calls.every(c=>["client_admin_status","client_admin_check"].includes(c))).toBe(true);}
async function close(page:Page,via:string){if(via==="navigation")await page.evaluate(()=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.navigate());else if(via==="escape")await page.keyboard.press("Escape");else await page.getByRole("button",{name:"Close joining permissions"}).click();await expect(page.locator("#client-admin-dialog")).not.toBeVisible();}

for(const [state,title] of Object.entries({pending:"Waiting for approval",active:"Approved at last check",declined:"Request declined",expired:"Request or permissions expired",revoked:"Joining permissions revoked",missing:"Request not found on the network computer"}))test(`read-only ${state} observation has an understandable outcome and next step`,async({page},testInfo)=>{
  if(state==="pending")await page.setViewportSize({width:390,height:844});
  await open(page,state);await expect(page.locator("#client-admin-state")).toHaveText("Check your saved request");
  await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-admin-state")).toHaveText(title);
  await expect(page.locator("#client-admin-permissions")).toContainText("Approve new devices joining your network");
  await expect(page.locator("#client-admin-host")).toHaveText("Home hub");await readonly(page);
  if(state==="pending")await page.screenshot({path:testInfo.outputPath("phone-pending-story.png"),fullPage:true});
});
test("empty, unsent, damaged and disconnected readiness never offers a mutation",async({page})=>{
  for(const [scenario,title] of Object.entries({none:"No joining permissions requested",reviewed:"Saved, not sent",attention:"Your saved request needs attention",disconnected:"Reconnect to check permissions",unjoined:"Join your network first",network_computer:"Review requests on this computer",unavailable:"Connect to your network computer"})) {
    await open(page,scenario);await expect(page.locator("#client-admin-state")).toHaveText(title);await expect(page.locator("#client-admin-check")).not.toBeVisible();
    expect(await page.locator("#client-admin-dialog button").allTextContents()).toEqual(["Close","Check status","Refresh"]);await readonly(page);
  }
});
test("old approval remains historical when a new check fails",async({page})=>{
  await open(page,"error");await page.getByText("Request and check details",{exact:true}).click();await expect(page.locator("#client-admin-history")).toContainText("Previously observed: approved");
  await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-admin-problem")).toContainText("saved request was not resent or replaced");
  await expect(page.locator("#client-admin-state")).toHaveText("Check your saved request");await expect(page.locator("#client-admin-history")).toContainText("not a new permission check");await readonly(page);
});
test("narrow layout keeps permissions legible and treats host names as text",async({page},testInfo)=>{
  await page.setViewportSize({width:390,height:844});await open(page,"unsafe");await expect(page.locator("#client-admin-host")).toHaveText("Hub <img src=x onerror=alert(1)>");
  await expect(page.locator("#client-admin-dialog img")).toHaveCount(0);const box=await page.locator("#client-admin-dialog").boundingBox();expect(box!.x).toBeGreaterThanOrEqual(0);expect(box!.width).toBeLessThanOrEqual(390);
  await page.screenshot({path:testInfo.outputPath("phone-joining-permissions.png"),fullPage:true});await readonly(page);
});
for(const via of ["button","escape","navigation"])test(`delayed load after ${via} cannot replace or unblock a reopened session`,async({page})=>{
  await page.goto("/tests/browser/client-admin.html?scenario=pending");const old=await hold(page,"client_admin_status");await page.getByRole("button",{name:"View joining permissions"}).click();await started(page,old);await close(page,via);
  const fresh=await hold(page,"client_admin_status");await page.getByRole("button",{name:"View joining permissions"}).click();await started(page,fresh);await release(page,old);
  await expect(page.locator("#client-admin-state")).toHaveText("Checking this device…");await expect(page.locator("#client-admin-refresh")).toBeDisabled();
  await release(page,fresh);await expect(page.locator("#client-admin-state")).toHaveText("Check your saved request");await expect(page.locator("#client-admin-refresh")).toBeEnabled();await readonly(page);
});
test("late check after navigation does not restore its result and explicit recheck reads current state",async({page})=>{
  await open(page,"pending");const check=await hold(page,"client_admin_check");await page.getByRole("button",{name:"Check status",exact:true}).click();await started(page,check);await close(page,"navigation");
  await page.getByRole("button",{name:"View joining permissions"}).click();await release(page,check);await expect(page.locator("#client-admin-state")).toHaveText("Check your saved request");
  await page.evaluate(()=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.setResult("revoked"));await page.getByRole("button",{name:"Check status",exact:true}).click();
  await expect(page.locator("#client-admin-state")).toHaveText("Joining permissions revoked");await readonly(page);
});
test("changing network context closes the old view and fences its delayed reply",async({page})=>{
  await open(page,"active");const check=await hold(page,"client_admin_check");await page.getByRole("button",{name:"Check status",exact:true}).click();await started(page,check);
  await page.evaluate(()=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.changeContext("native-work-context"));await expect(page.locator("#client-admin-dialog")).not.toBeVisible();
  await page.getByRole("button",{name:"View joining permissions"}).click();await expect(page.locator("#client-admin-network")).toHaveText("Work network");await release(page,check);
  await expect(page.locator("#client-admin-network")).toHaveText("Work network");await expect(page.locator("#client-admin-state")).toHaveText("Check your saved request");await readonly(page);
});
test("a reply for a different native context cannot present a fresh approval",async({page})=>{
  await open(page,"active");await page.evaluate(()=>(window as unknown as {fixtureClientControl:Control}).fixtureClientControl.setCheckContext("foreign-context"));
  await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-admin-problem")).toContainText("network or saved request changed");
  await expect(page.locator("#client-admin-state")).toHaveText("Check your saved request");await readonly(page);
});
