// Sign in against the Vite + Express starter, so the analyzer sees the
// post-login cookies rather than only the empty landing page.
export default async ({ page }) => {
  await page.click('#login');
  await page.waitForFunction(() => document.querySelector('#out')?.textContent?.length > 2, { timeout: 10000 });
};
