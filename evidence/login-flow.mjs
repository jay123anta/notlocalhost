/**
 * The flow script used for the evidence runs against the fixture app.
 *
 * A flow script default-exports an async function and receives a live
 * Playwright page. Instrumentation is already installed, so everything this
 * does -- the POST, the redirect, the cookies that come back -- is analyzed.
 */
export default async ({ page, log }) => {
  await page.fill('#email', 'dev@example.com');
  await page.fill('#password', 'hunter2');
  await page.click('#login button[type=submit]');
  await page.waitForURL('**/dashboard');
  log?.('signed in, now on the dashboard');
};
