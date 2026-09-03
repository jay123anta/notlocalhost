// Register and sign in on a stock Laravel Breeze install. Breeze's register
// route logs the new user in, which is the shortest path to the authenticated
// cookie set (laravel_session rotated, plus remember_web_* if requested).
export default async ({ page, log }) => {
  await page.goto(new URL('/register', page.url()).href);
  const email = `dev${Date.now()}@example.com`;
  await page.fill('#name', 'Dev User');
  await page.fill('#email', email);
  await page.fill('#password', 'password123');
  await page.fill('#password_confirmation', 'password123');
  await page.click('button[type=submit]');
  await page.waitForURL('**/dashboard', { timeout: 20000 });
  log?.(`registered and signed in as ${email}`);
};
