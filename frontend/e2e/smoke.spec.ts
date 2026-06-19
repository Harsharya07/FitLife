import { test, expect } from '@playwright/test';

test('signup, log workout, dashboard shows activity', async ({ page }) => {
  const username = `e2e_${Date.now()}`;

  await page.goto('/signup');
  await page.getByPlaceholder('Username').fill(username);
  await page.getByPlaceholder('Password', { exact: true }).fill('testpass123');
  await page.getByPlaceholder('Confirm Password').fill('testpass123');
  await page.getByRole('button', { name: 'Create Account' }).click();

  await expect(page).toHaveURL(/dashboard/, { timeout: 15000 });

  const skip = page.getByRole('button', { name: 'Skip' });
  if (await skip.isVisible({ timeout: 3000 }).catch(() => false)) {
    await skip.click();
  }

  await page.goto('/exercises');
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: 'Log', exact: true }).first().click();
  await page.getByRole('button', { name: 'Log Workout' }).click();

  await page.goto('/activity');
  await expect(page.getByText(/sets|Logged/i).first()).toBeVisible({ timeout: 10000 });
});
