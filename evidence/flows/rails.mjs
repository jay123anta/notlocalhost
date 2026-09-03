// Sign in against a stock `rails new` + `rails generate authentication` app.
// Rails rotates the session cookie on sign-in, so the interesting cookie only
// exists after the POST.
export default async ({ page, log }) => {
  await page.fill('#email_address', 'dev@example.com');
  await page.fill('#password', 'password123');
  await page.click('input[type=submit]');
  await page.waitForLoadState('networkidle');
  log?.('signed in');
};
