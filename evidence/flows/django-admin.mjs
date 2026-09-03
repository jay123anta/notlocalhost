// Log in to the Django admin, which is what a stock `django-admin startproject`
// gives you. The csrftoken cookie is set on the login page; sessionid only
// appears after the POST succeeds.
export default async ({ page }) => {
  await page.fill('#id_username', 'dev');
  await page.fill('#id_password', 'devpassword123');
  await page.click('input[type=submit]');
  await page.waitForURL('**/admin/', { timeout: 15000 });
};
