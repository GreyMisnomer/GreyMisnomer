const { test, expect } = require('@playwright/test');

test.describe('Stage 2.7: In-Browser Mempool & Transaction Tracker ($0 Infrastructure)', () => {

  test('Topbar & Sidebar: Opens Mempool Tracker modal with filter tabs and badge counters', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Verify topbar button exists and displays badge
    const topbarBtn = page.locator('#btnMempoolTracker');
    await expect(topbarBtn).toBeVisible();

    // Click topbar Mempool button
    await topbarBtn.click();
    const modal = page.locator('#modalMempool');
    await expect(modal).toHaveClass(/show/);

    // Verify filter tabs are rendered
    await expect(page.locator('#tabMempoolAll')).toBeVisible();
    await expect(page.locator('#tabMempoolPending')).toBeVisible();
    await expect(page.locator('#tabMempoolSequenced')).toBeVisible();
    await expect(page.locator('#tabMempoolRejected')).toBeVisible();

    // Verify list container has transaction cards
    const cards = page.locator('#mempoolListContainer .mempool-card');
    await expect(cards.first()).toBeVisible({ timeout: 5000 });
    const count = await cards.count();
    expect(count).toBeGreaterThan(0);

    // Test filter tabs: Click "Sequenced"
    await page.click('#tabMempoolSequenced');
    await expect(page.locator('#tabMempoolSequenced')).toHaveClass(/active/);
    const sequencedCards = page.locator('#mempoolListContainer .mempool-card.sequenced');
    const seqCount = await sequencedCards.count();
    expect(seqCount).toBeGreaterThan(0);

    // Verify receipt metrics inside sequenced card
    const receiptBox = page.locator('.mempool-receipt-box').first();
    await expect(receiptBox).toBeVisible();
    await expect(receiptBox).toContainText('Receipt');

    // Test filter tabs: Click "Rejected"
    await page.click('#tabMempoolRejected');
    await expect(page.locator('#tabMempoolRejected')).toHaveClass(/active/);
    const rejectedCards = page.locator('#mempoolListContainer .mempool-card.rejected');
    expect(await rejectedCards.count()).toBeGreaterThan(0);

    // Close modal
    await page.click('#modalMempool .modal-close-btn');
    await expect(modal).not.toHaveClass(/show/);

    // Test opening from sidebar navigation item
    const sidebarNav = page.locator('#nav-mempool');
    await expect(sidebarNav).toBeVisible();
    await sidebarNav.click();
    await expect(modal).toHaveClass(/show/);
    await page.click('#modalMempool .modal-close-btn');
  });

  test('Sovereign Intent Builder: Direct Handoff to Mempool Tracker upon submission', async ({ page, context }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Navigate to Sovereign Signer
    await page.click('#nav-signer');
    await expect(page.locator('#view-signer')).toHaveClass(/active/);

    // Auto-detect next op_index to make simulation pass
    await page.click('button:has-text("Auto-detect")');

    // Sign Intent & Simulate in WASM
    const btnSign = page.locator('#btnSignIntent');
    await btnSign.click();

    // Verify successful pre-flight simulation
    const simBadge = page.locator('#simBadge');
    await expect(simBadge).toContainText('VALID', { timeout: 10000 });

    // Verify Submission Assistant box is visible with "Track in Mempool" button
    const assistantBox = page.locator('#submissionAssistantBox');
    await expect(assistantBox).toBeVisible();
    const btnTrack = page.locator('#btnTrackInMempool');
    await expect(btnTrack).toBeVisible();

    // Intercept window.open so the test doesn't pop up external page
    await page.evaluate(() => {
      window.open = (url) => { console.log('Mock window.open called with:', url); };
    });

    // Click "Submit via GitHub Issue"
    await page.click('button:has-text("Submit via GitHub Issue")');

    // Click "Track in Mempool"
    await btnTrack.click();

    // Verify Mempool modal opens and contains the submitted pending transaction
    const modal = page.locator('#modalMempool');
    await expect(modal).toHaveClass(/show/);

    const pendingCard = page.locator('#mempoolListContainer .mempool-card.pending').first();
    await expect(pendingCard).toBeVisible({ timeout: 10000 });

    // Verify the pending badge is active
    const pendingBadge = pendingCard.locator('.mempool-badge.pending');
    await expect(pendingBadge).toBeVisible();
    await expect(pendingBadge).toContainText('Pending');
  });

  test('Mempool Controls: Demo Mode toggle & Refresh functionality', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Open Mempool Modal
    await page.click('#btnMempoolTracker');
    const modal = page.locator('#modalMempool');
    await expect(modal).toHaveClass(/show/);

    // Click "Demo Data" button to toggle mode
    const demoBtn = page.locator('#btnToggleMockMempool');
    await expect(demoBtn).toBeVisible();
    await demoBtn.click();

    // Click Refresh button
    const refreshBtn = page.locator('#btnRefreshMempool');
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    // Verify cards are populated
    const cards = page.locator('#mempoolListContainer .mempool-card');
    await expect(cards.first()).toBeVisible({ timeout: 5000 });
    expect(await cards.count()).toBeGreaterThan(0);
  });

});
