const { test, expect } = require('@playwright/test');

test.describe('End-to-End Carbon Credit Lifecycle', () => {

  test('Full protocol lifecycle: Project -> MRV -> Merkle -> PoI -> Mint -> Retire -> PoO -> Audit Invariants', async ({ page }) => {
    // 1. Visit App
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // 2. Developer registers a project
    await page.selectOption('#roleSwitcher', 'developer');
    await page.click('#nav-projects');
    await expect(page.locator('#view-projects')).toHaveClass(/active/);

    await page.fill('#prj-name', 'Sundarbans Mangrove Project');
    await page.fill('#prj-id', 'PRJ-MANGROVE-001');
    await page.fill('#prj-credits', '1000');
    await page.click('button:has-text("Register Project")');

    // Confirm project in table
    const prjList = page.locator('#projectsList');
    await expect(prjList).toContainText('PRJ-MANGROVE-001');

    // 3. Developer uploads MRV Data and generates BLAKE3 Merkle Root
    await page.click('#nav-mrv');
    await expect(page.locator('#view-mrv')).toHaveClass(/active/);

    await page.selectOption('#mrv-project-select', 'PRJ-MANGROVE-001');
    await page.click('button:has-text("Seed Demo Dataset")');
    await page.click('button:has-text("Compute Merkle Tree Commitment")');

    // Verify Merkle Root generated
    const mrvCommitmentCard = page.locator('#mrvCommitmentDisplay');
    await expect(mrvCommitmentCard).toBeVisible({ timeout: 5000 });
    await expect(mrvCommitmentCard).toContainText('BLAKE3 Merkle Root');

    // 4. Validator issues Proof-of-Integrity (PoI)
    await page.selectOption('#roleSwitcher', 'validator');
    await page.click('#nav-verification');
    await expect(page.locator('#view-verification')).toHaveClass(/active/);

    // Find and approve the PoI for PRJ-MANGROVE-001
    const approveBtn = page.locator('button:has-text("Approve & Issue PoI")').first();
    await expect(approveBtn).toBeVisible({ timeout: 5000 });
    await approveBtn.click();

    // Verify status changes to Approved
    await expect(page.locator('#badge-verification')).toHaveText('0');

    // 5. Developer mints credits
    await page.selectOption('#roleSwitcher', 'developer');
    await page.click('#nav-projects');
    const mintBtn = page.locator('button:has-text("Mint")').first();
    await expect(mintBtn).toBeVisible();
    await mintBtn.click();

    // Verify navigation to registry and batch created
    await expect(page.locator('#view-registry')).toHaveClass(/active/, { timeout: 5000 });
    await expect(page.locator('#reg-total-batches')).toHaveText('1');
    await expect(page.locator('#reg-total-active')).toContainText('1,000');

    // 6. Navigate to Portfolio & execute partial retirement
    await page.click('#nav-portfolio');
    await expect(page.locator('#view-portfolio')).toHaveClass(/active/);

    // Check pre-filled retirement range and click Execute Retirement
    const retireBtn = page.locator('button:has-text("Execute Retirement")').first();
    await expect(retireBtn).toBeVisible({ timeout: 5000 });
    await retireBtn.click();

    // Verify PoO Receipt generated with Export PDF Certificate and Download JSON Receipt buttons
    const pooReceipt = page.locator('h4:has-text("PoO Receipt")').first();
    await expect(pooReceipt).toBeVisible({ timeout: 5000 });
    await expect(page.locator('button:has-text("Export PDF Certificate")').first()).toBeVisible();
    await expect(page.locator('button:has-text("Download JSON Receipt")').first()).toBeVisible();

    // 7. Audit view verification of in-memory session invariants
    await page.click('#nav-audit');
    await expect(page.locator('#view-audit')).toHaveClass(/active/);

    // Verify metrics: Original 1000, Retired 300 (default partial range 1000000 - 1000299 = 300)
    await expect(page.locator('#cnt-original')).toContainText(/1,?000/);
    await expect(page.locator('#cnt-retired')).toContainText('300');
    await expect(page.locator('#cnt-active')).toContainText('700');

    // Verify all 7 session invariants PASS
    const auditCards = page.locator('#auditGrid .audit-card');
    await expect(auditCards).toHaveCount(7);
    for (let i = 0; i < 7; i++) {
      await expect(auditCards.nth(i)).toHaveClass(/ok/);
    }
  });

});
