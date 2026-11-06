import {defineConfig} from "@playwright/test";
export default defineConfig({
  testDir:"tests/browser",testMatch:"**/*.spec.ts",fullyParallel:true,
  retries:0,reporter:"list",timeout:30000,
  use:{baseURL:"http://127.0.0.1:1431",channel:"chrome",headless:true,trace:"retain-on-failure"},
  webServer:{command:"npm run dev -- --host 127.0.0.1 --port 1431 --strictPort",url:"http://127.0.0.1:1431/tests/browser/host-admin.html",reuseExistingServer:false,timeout:30000},
});
