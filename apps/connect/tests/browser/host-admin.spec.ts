import {test,expect,type Page} from "@playwright/test";
async function open(page:Page,scenario:string) {
  await page.goto(`/tests/browser/host-admin.html?scenario=${scenario}`);
  await page.getByRole("button",{name:"Manage administrators",exact:true}).click();
  await expect(page.locator("#host-admin-network")).toHaveText("Home network");
}
async function countCommits(page:Page) {
  return page.evaluate(()=>((window as unknown as {fixtureAdminCalls:string[]}).fixtureAdminCalls).filter(v=>v==="host_admin_commit").length);
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
