import {test,expect,type Page} from "@playwright/test";
type Control={holdNext(command:string):number;started(id:number):boolean;release(id:number):void;navigate():void;changeContext():void;setMismatch(value:string):void;permissionsOpened():number};
async function open(page:Page,scenario="approved"){await page.goto(`/tests/browser/client-requests.html?scenario=${scenario}`);await page.getByRole("button",{name:"View saved device request"}).click();await expect(page.locator("#client-requests-network")).toHaveText(scenario==="load-error"?"Your network":"Home network");}
async function readonly(page:Page){const calls=await page.evaluate(()=>(window as unknown as {fixtureRequestCalls:{command:string;args:object}[]}).fixtureRequestCalls);expect(calls.every(c=>["client_requests_status","client_requests_check"].includes(c.command)&&Object.keys(c.args).length===0)).toBe(true);}
async function hold(page:Page,command:string){return page.evaluate(c=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.holdNext(c),command);}
async function started(page:Page,id:number){await expect.poll(()=>page.evaluate(id=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.started(id),id)).toBe(true);}
async function release(page:Page,id:number){await page.evaluate(id=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.release(id),id);}
async function close(page:Page,via:string){if(via==="escape")await page.keyboard.press("Escape");else if(via==="navigation")await page.evaluate(()=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.navigate());else await page.getByRole("button",{name:"Close device request"}).click();await expect(page.locator("#client-requests-dialog")).not.toBeVisible();}
for(const [scenario,title] of Object.entries({approved:"Approval confirmed at last check",rejected:"Rejection confirmed at last check",queue:"Saved queue check confirmed"}))test(`original ${scenario} result needs an explicit check and has a clear story`,async({page},info)=>{
 if(scenario==="approved")await page.setViewportSize({width:390,height:844});await open(page,scenario);
 await expect(page.locator("#client-requests-state")).toHaveText("Check this device request");
 await expect(page.locator("#client-requests-history")).toContainText(scenario==="queue"?"snapshot":"recorded earlier");
 await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-requests-state")).toHaveText(title);
 await expect(page.locator("#client-requests-next")).not.toBeEmpty();await readonly(page);
 if(scenario==="queue")await expect(page.locator("#client-requests-description")).toContainText("was waiting");
 if(scenario==="approved"){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.screenshot({path:info.outputPath("phone-saved-request.png"),fullPage:true});}
});
for(const [scenario,title] of Object.entries({started:"Request still unconfirmed",unconfirmed:"Result still unclear"}))test(`${scenario} never becomes completed approval`,async({page})=>{
 await open(page,scenario);await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-requests-state")).toHaveText(title);await readonly(page);
 if(scenario==="unconfirmed")await expect(page.locator("#client-requests-history")).toContainText("history, not a new confirmation");
});
test("empty, unsent, retired, damaged and unavailable states have no send, retry or approval controls",async({page})=>{
 for(const [scenario,title] of Object.entries({empty:"No saved device request",reviewed:"Saved, not sent",archived:"Earlier request retained",attention:"Saved request needs attention",unavailable:"Device approval controls are not available yet",disconnected:"Reconnect to check this request",unjoined:"Join your network first",authority_host:"Manage devices on this host"})){
  await open(page,scenario);await expect(page.locator("#client-requests-state")).toHaveText(title);await expect(page.locator("#client-requests-check")).not.toBeVisible();
  expect(await page.locator("#client-requests-dialog button").allTextContents()).toEqual(["Close","Check status","Refresh this device","Joining permissions"]);await readonly(page);
 }
});
test("failed readback retains earlier evidence and sanitizes native diagnostics",async({page})=>{
 await open(page,"error");await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-requests-problem")).toContainText("not resent");
 await expect(page.locator("#client-requests-state")).toHaveText("Check this device request");await expect(page.locator("#client-requests-history")).toContainText("history, not a new confirmation");
 await expect(page.locator("#client-requests-dialog")).not.toContainText("private/key.json");await readonly(page);
});
for(const command of ["client_requests_status","client_requests_check"])for(const via of ["button","escape","navigation"])test(`late ${command} after ${via} cannot restore an old presentation`,async({page})=>{
 await open(page);const id=await hold(page,command);
 await page.getByRole("button",{name:command.endsWith("status")?"Refresh this device":"Check status",exact:true}).click();await started(page,id);await close(page,via);
 await page.getByRole("button",{name:"View saved device request"}).click();await expect(page.locator("#client-requests-state")).toHaveText("Check this device request");await release(page,id);
 await expect(page.locator("#client-requests-state")).toHaveText("Check this device request");await expect(page.locator("#client-requests-refresh")).toBeEnabled();await readonly(page);
});
test("network changes close the old request and fence its delayed result",async({page})=>{
 await open(page);const id=await hold(page,"client_requests_check");await page.getByRole("button",{name:"Check status",exact:true}).click();await started(page,id);
 await page.evaluate(()=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.changeContext());await expect(page.locator("#client-requests-dialog")).not.toBeVisible();
 await page.getByRole("button",{name:"View saved device request"}).click();await expect(page.locator("#client-requests-network")).toHaveText("Work network");await release(page,id);
 await expect(page.locator("#client-requests-network")).toHaveText("Work network");await expect(page.locator("#client-requests-state")).toHaveText("Check this device request");await readonly(page);
});
test("foreign native context, operation, candidate or saved reference cannot present confirmation",async({page})=>{
 for(const field of ["context","nonce","digest","operation","name","code"]){await open(page);await page.evaluate(v=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.setMismatch(v),field);
  await page.getByRole("button",{name:"Check status",exact:true}).click();await expect(page.locator("#client-requests-problem")).toContainText("network or saved request changed");await expect(page.locator("#client-requests-state")).toHaveText("Check this device request");await readonly(page);}
});
test("device and host names remain plain text, and joining permissions provides a clear next destination",async({page})=>{
 await open(page,"unsafe");await expect(page.locator("#client-requests-action")).toContainText("<img");expect(await page.locator("#client-requests-dialog img").count()).toBe(0);
 await page.getByRole("button",{name:"Joining permissions",exact:true}).click();await expect(page.locator("#client-requests-dialog")).not.toBeVisible();
 expect(await page.evaluate(()=>(window as unknown as {fixtureRequestControl:Control}).fixtureRequestControl.permissionsOpened())).toBe(1);await readonly(page);
});

test("failed local inspection has a refresh path instead of a stuck loading state",async({page})=>{
 await open(page,"load-error");await expect(page.locator("#client-requests-state")).toHaveText("Could not read this device");
 await expect(page.locator("#client-requests-refresh")).toBeEnabled();await expect(page.locator("#client-requests-check")).not.toBeVisible();
 await expect(page.locator("#client-requests-problem")).not.toContainText("Private loader");await readonly(page);
});
