const { test, expect } = require('@playwright/test');

test.describe('RFC-006 Sovereign Key Manager & In-Browser Intent Signer', () => {

  test('Key Manager opens, switches preset identities, and generates new Ed25519 keypair', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Open Key Manager modal
    await page.click('#btnKeyManager');
    const modal = page.locator('#modalKeyManager');
    await expect(modal).toHaveClass(/show/);

    // Verify default active key is Infosys Buyer
    const pubKeyText = page.locator('#modalActivePubkey');
    await expect(pubKeyText).toContainText('3fec9121bb0c0204');

    // Switch to Tata Solar Developer using preset button
    await page.click('#presetActorGrid button:has-text("Tata Solar Developer")');
    await expect(pubKeyText).toContainText('dcc59196196d6c68');
    await expect(page.locator('#topbarKeyLabel')).toContainText('Tata');

    // Generate brand new keypair
    await page.click('button:has-text("Generate Fresh Keypair")');
    const newPub = await pubKeyText.textContent();
    expect(newPub.length).toBe(64);
    expect(newPub).not.toContain('dcc59196196d6c68');

    // Close modal
    await page.click('#modalKeyManager .modal-close-btn');
    await expect(modal).not.toHaveClass(/show/);
  });

  test('Signer view: Select Infosys, sign valid Transfer intent, verify WASM pre-flight simulation and canonical line', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Ensure Infosys is the selected key
    await page.click('#btnKeyManager');
    await page.click('#presetActorGrid button:has-text("Infosys Corporate Buyer")');
    await page.click('#modalKeyManager .modal-close-btn');

    // Navigate to Signer tab
    await page.click('#nav-signer');
    await expect(page.locator('#view-signer')).toHaveClass(/active/);

    // In events.jsonl, CC-IN-SOLAR-2026-001 has been transferred to Infosys at op_index 1
    // The next op_index for Infosys is 2
    await page.fill('#tx-credit-id', 'CC-IN-SOLAR-2026-001');
    await page.fill('#tx-recipient-pubkey', 'dcc59196196d6c686652e43f1303665c79edaba5e07834a910ddd1c057576a8a');
    await page.fill('#tx-op-index', '2');

    // Click Sign & Simulate
    await page.click('#btnSignIntent');

    // Verify valid simulation banner
    const banner = page.locator('#simBanner');
    await expect(banner).toHaveClass(/valid/, { timeout: 10000 });
    await expect(banner).toContainText('Pre-flight simulation SUCCESS');

    // Verify canonical line output box
    const canonicalBox = page.locator('#canonicalLineBox');
    const lineText = await canonicalBox.textContent();
    expect(lineText).toContain('"type":"transfer"');
    expect(lineText).toContain('"credit_id":"CC-IN-SOLAR-2026-001"');
    expect(lineText).toContain('"op_index":2');
    expect(lineText).toContain('"owner_sig":"');

    // Verify submission assistant is displayed
    await expect(page.locator('#submissionAssistantBox')).toBeVisible();
    await expect(page.locator('#btnCopyCanonical')).toBeEnabled();
  });

  test('Signer view: Rejects unauthorized transfer when non-owner attempts to sign', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Switch active key to Tata Solar (who is NOT current owner of CC-IN-SOLAR-2026-001 at op_index 2)
    await page.click('#btnKeyManager');
    await page.click('#presetActorGrid button:has-text("Tata Solar Developer")');
    await page.click('#modalKeyManager .modal-close-btn');

    // Navigate to Signer tab
    await page.click('#nav-signer');

    // Attempt to transfer CC-IN-SOLAR-2026-001
    await page.fill('#tx-credit-id', 'CC-IN-SOLAR-2026-001');
    await page.fill('#tx-recipient-pubkey', '3fec9121bb0c0204f46e5401f552ccb23bcba63e6e745d1cc2dbbe70f9c0ba28');
    await page.fill('#tx-op-index', '2');

    // Click Sign & Simulate
    await page.click('#btnSignIntent');

    // Verify rejection banner
    const banner = page.locator('#simBanner');
    await expect(banner).toHaveClass(/invalid/, { timeout: 10000 });
    await expect(banner).toContainText('WASM Pre-Flight Rejection');
    await expect(banner).toContainText('credit owner mismatch');

    // Verify canonical line box shows rejection comment
    const canonicalBox = page.locator('#canonicalLineBox');
    await expect(canonicalBox).toContainText('rejected by the state machine');
  });

  test('Signer view: Burn / Retire form simulation and op_index replay prevention', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Ensure Infosys is the selected key
    await page.click('#btnKeyManager');
    await page.click('#presetActorGrid button:has-text("Infosys Corporate Buyer")');
    await page.click('#modalKeyManager .modal-close-btn');

    // Navigate to Signer tab and switch to Burn tab
    await page.click('#nav-signer');
    await page.click('#btnTabBurn');
    await expect(page.locator('#formSignerBurn')).toBeVisible();

    // Fill valid burn for CC-IN-SOLAR-2026-001 (active range: 1000400-1000999, owner Infosys, op_index 2)
    await page.fill('#burn-credit-id', 'CC-IN-SOLAR-2026-001');
    await page.fill('#burn-range-start', '1000400');
    await page.fill('#burn-range-end', '1000599');
    await page.fill('#burn-beneficiary', 'Infosys Net-Zero Campus Bengaluru');
    await page.fill('#burn-op-index', '2');

    // Click Sign & Simulate
    await page.click('#btnSignIntent');

    // Verify valid simulation
    const banner = page.locator('#simBanner');
    await expect(banner).toHaveClass(/valid/, { timeout: 10000 });

    // Now tamper op_index to 5 (replay index mismatch)
    await page.fill('#burn-op-index', '5');
    await page.click('#btnSignIntent');

    // Verify rejection due to op_index mismatch
    await expect(banner).toHaveClass(/invalid/, { timeout: 10000 });
    await expect(banner).toContainText('operation index mismatch');
  });

});
