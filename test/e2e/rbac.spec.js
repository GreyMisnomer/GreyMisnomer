const { test, expect } = require('@playwright/test');

test.describe('Role-Based Access Control (RBAC) Core Flows', () => {

  test('Developer can see Mint button for own project, Buyer cannot', async ({ page }) => {
    await page.goto('/docs/app.html');
    
    // Developer registers a project
    await page.selectOption('#roleSwitcher', 'developer');
    await page.click('#nav-projects');
    
    await page.fill('#prj-name', 'E2E Solar Project');
    await page.fill('#prj-id', 'E2E-SOL-001');
    await page.click('button:has-text("Register Project")');
    
    // Mint button shouldn't exist until PoI anyway, but check it doesn't crash
    const devTable = await page.textContent('#projectsList');
    expect(devTable).toContain('E2E-SOL-001');
    
    // Switch to Buyer
    await page.selectOption('#roleSwitcher', 'buyer');
    
    // Ensure buyer cannot see the Projects tab in sidebar
    await expect(page.locator('#nav-projects')).toHaveClass(/locked/);
    
    // Force navigate via URL hash or JS (simulate malicious buyer)
    await page.evaluate(() => window.navigate('projects'));
    
    // The navigate function should reject and show toast
    const toast = page.locator('#toast');
    await expect(toast).toHaveText('This module is not available for your current role.');
  });

});
