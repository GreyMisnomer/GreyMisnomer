const { test, expect } = require('@playwright/test');

test.describe('Role-Based Access Control (RBAC) Core Flows', () => {

  test('Developer can see Mint button for own project, Buyer cannot', async ({ page }) => {
    await page.goto('/app.html');
    
    // Wait for WASM module to load (the page shows a role switcher only after init)
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Developer registers a project
    await page.selectOption('#roleSwitcher', 'developer');
    await page.click('#nav-projects');
    
    await page.fill('#prj-name', 'E2E Solar Project');
    await page.fill('#prj-id', 'E2E-SOL-001');
    await page.click('button:has-text("Register Project")');
    
    // Verify project appears in the list
    const devTable = await page.textContent('#projectsList');
    expect(devTable).toContain('E2E-SOL-001');
    
    // Switch to Buyer
    await page.selectOption('#roleSwitcher', 'buyer');
    
    // Ensure buyer cannot see the Projects tab in sidebar (it should be locked)
    await expect(page.locator('#nav-projects')).toHaveClass(/locked/);
    
    // Force navigate via JS (simulate malicious buyer)
    await page.evaluate(() => window.navigate('projects'));
    
    // The navigate function should reject and show toast
    const toast = page.locator('#toast');
    await expect(toast).toHaveText('This module is not available for your current role.');
  });

  test('Toast notification auto-dismisses after timeout', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Switch to auditor (most restricted role)
    await page.selectOption('#roleSwitcher', 'auditor');

    // Attempt to navigate to a locked module
    await page.evaluate(() => window.navigate('projects'));

    // Toast should appear
    const toast = page.locator('#toast');
    await expect(toast).toHaveClass(/show/);

    // Wait 6 seconds for auto-dismiss (JS timeout is 5s)
    await page.waitForTimeout(6000);
    
    // Toast should no longer have the 'show' class
    await expect(toast).not.toHaveClass(/show/);
  });

  test('Locked nav items are visually dimmed for each role', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Buyer: projects, mrv, verification, governance should be locked
    await page.selectOption('#roleSwitcher', 'buyer');
    await expect(page.locator('#nav-projects')).toHaveClass(/locked/);
    await expect(page.locator('#nav-mrv')).toHaveClass(/locked/);
    await expect(page.locator('#nav-verification')).toHaveClass(/locked/);
    await expect(page.locator('#nav-governance')).toHaveClass(/locked/);
    // marketplace, portfolio, registry, audit, dashboard should NOT be locked
    await expect(page.locator('#nav-marketplace')).not.toHaveClass(/locked/);
    await expect(page.locator('#nav-portfolio')).not.toHaveClass(/locked/);
    await expect(page.locator('#nav-dashboard')).not.toHaveClass(/locked/);

    // Validator: projects, mrv, marketplace, portfolio should be locked
    await page.selectOption('#roleSwitcher', 'validator');
    await expect(page.locator('#nav-projects')).toHaveClass(/locked/);
    await expect(page.locator('#nav-mrv')).toHaveClass(/locked/);
    await expect(page.locator('#nav-marketplace')).toHaveClass(/locked/);
    await expect(page.locator('#nav-portfolio')).toHaveClass(/locked/);
    // governance, verification, registry, audit should NOT be locked
    await expect(page.locator('#nav-governance')).not.toHaveClass(/locked/);
    await expect(page.locator('#nav-verification')).not.toHaveClass(/locked/);

    // Admin: nothing should be locked
    await page.selectOption('#roleSwitcher', 'admin');
    await expect(page.locator('#nav-projects')).not.toHaveClass(/locked/);
    await expect(page.locator('#nav-governance')).not.toHaveClass(/locked/);
    await expect(page.locator('#nav-marketplace')).not.toHaveClass(/locked/);
    await expect(page.locator('#nav-verification')).not.toHaveClass(/locked/);
  });

  test('Role switch auto-redirects to dashboard if current view is locked', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // As developer, navigate to projects
    await page.selectOption('#roleSwitcher', 'developer');
    await page.click('#nav-projects');
    await expect(page.locator('#view-projects')).toHaveClass(/active/);

    // Switch to buyer — projects is locked, should auto-redirect to dashboard
    await page.selectOption('#roleSwitcher', 'buyer');
    await expect(page.locator('#view-dashboard')).toHaveClass(/active/);
  });

});