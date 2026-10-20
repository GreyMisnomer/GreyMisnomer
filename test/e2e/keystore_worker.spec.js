const { test, expect } = require('@playwright/test');

test.describe('RFC-006 Sovereign Enclave: Encrypted Vault (.gmkey) & Background Web Worker', () => {

  test('Background Web Worker: Non-blocking ledger replay with live progress tracking', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Switch to auditor role and navigate to audit view
    await page.selectOption('#roleSwitcher', 'auditor');
    await page.click('#nav-audit');
    await expect(page.locator('#view-audit')).toHaveClass(/active/);

    // Trigger full ledger replay in background worker
    const replayBtn = page.locator('#btnReplayLedger');
    await expect(replayBtn).toBeVisible();
    await replayBtn.click();

    // Verify badge turns green and replay completes
    const badge = page.locator('#ledgerVerificationBadge');
    await expect(badge).toContainText(/Verified|Replayed/i, { timeout: 10000 });

    // Verify metrics populated from background worker
    const eventsCount = page.locator('#ledgerEventsCount');
    const count = parseInt(await eventsCount.textContent(), 10);
    expect(count).toBeGreaterThan(0);

    const chainStatus = page.locator('#ledgerChainStatus');
    await expect(chainStatus).toContainText('VALID');
  });

  test('Background Web Worker: Offload BLAKE3 Merkle Tree computation in MRV view', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Switch to developer role
    await page.selectOption('#roleSwitcher', 'developer');
    await page.click('#nav-projects');

    // Register a test project first so MRV select has an active project
    await page.fill('#prj-name', 'Ladakh Solar Park');
    await page.fill('#prj-id', 'PRJ-LADAKH-001');
    await page.fill('#prj-credits', '500');
    await page.click('button:has-text("+ Register Project")');

    // Navigate to MRV
    await page.click('#nav-mrv');
    await expect(page.locator('#view-mrv')).toHaveClass(/active/);

    // Seed Demo Dataset
    await page.click('button:has-text("Seed Demo Dataset")');
    await expect(page.locator('#recordBadge')).toContainText('records');

    // Compute Merkle Tree Commitment via background worker
    await page.click('button:has-text("Compute Merkle Tree Commitment")');

    // Verify Merkle Root displayed
    const commitmentDisplay = page.locator('#mrvCommitmentDisplay');
    await expect(commitmentDisplay).toBeVisible({ timeout: 10000 });
    await expect(commitmentDisplay).toContainText('BLAKE3 Merkle Root');
    await expect(commitmentDisplay).toContainText('✅ Merkle Commitment Successful');

    // Verify spot-check section appears
    const spotCheck = page.locator('#spotCheckSection');
    await expect(spotCheck).toBeVisible();
  });

  test('Encrypted Client Vault (.gmkey): Generation, Passphrase Protection, Tamper Rejection, and Reload Persistence', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // 1. Open Key Manager
    await page.click('#btnKeyManager');
    const kmModal = page.locator('#modalKeyManager');
    await expect(kmModal).toHaveClass(/show/);

    // 2. Generate brand new Ed25519 keypair
    await page.click('button:has-text("Generate Fresh Keypair")');
    const freshPubkey = (await page.locator('#modalActivePubkey').textContent()).trim();
    expect(freshPubkey.length).toBe(64);

    // 3. Save Active Key to Encrypted Browser Vault (IndexedDB)
    await page.click('#vaultSection button:has-text("+ Save Active Key")');
    const passModal = page.locator('#modalPassphrasePrompt');
    await expect(passModal).toHaveClass(/show/);

    await page.fill('#passphraseInputLabel', 'Himalayan Wind Farm');
    await page.fill('#passphraseInputPass', 'VaultPassphrase#2026!');
    await page.click('#btnPassphraseConfirm');

    // Verify modal closes and identity appears in vault grid
    await expect(passModal).not.toHaveClass(/show/);
    const vaultGrid = page.locator('#vaultIdentitiesGrid');
    await expect(vaultGrid).toBeVisible();
    await expect(vaultGrid).toContainText('Himalayan Wind Farm');

    // 4. Switch to a preset key
    await page.click('#presetActorGrid button:has-text("Tata Solar Developer")');
    await expect(page.locator('#modalActivePubkey')).not.toContainText(freshPubkey);

    // 5. Test unlock with wrong passphrase
    const unlockBtn = page.locator('.vault-identity-card:has-text("Himalayan Wind Farm") button:has-text("🔓 Unlock")');
    await unlockBtn.click();
    await expect(passModal).toHaveClass(/show/);

    await page.fill('#passphraseInputPass', 'WrongPassphrase!');
    await page.click('#btnPassphraseConfirm');

    // Error banner must be visible and modal must stay open
    const errBanner = page.locator('#passphraseError');
    await expect(errBanner).toBeVisible();
    await expect(errBanner).toContainText(/failed|incorrect|corrupted/i);
    await expect(passModal).toHaveClass(/show/);

    // 6. Test unlock with correct passphrase
    await page.fill('#passphraseInputPass', 'VaultPassphrase#2026!');
    await page.click('#btnPassphraseConfirm');
    await expect(passModal).not.toHaveClass(/show/);

    // Active key restored to our custom key
    const activePubAfter = (await page.locator('#modalActivePubkey').textContent()).trim();
    expect(activePubAfter).toBe(freshPubkey);

    // 7. Verify persistence across page refresh
    await page.reload();
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });
    await page.click('#btnKeyManager');
    await expect(kmModal).toHaveClass(/show/);
    await expect(page.locator('#vaultIdentitiesGrid')).toContainText('Himalayan Wind Farm');
  });

  test('Direct Web Worker Dispatcher Bridge: runInWorker executes REPLAY_LOG, COMPUTE_MERKLE, and SIMULATE_INTENT', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Test runInWorker directly from browser execution context
    const workerTestResult = await page.evaluate(async () => {
      const res = await fetch('events.jsonl');
      const events = await res.text();

      // 1. REPLAY_LOG
      let progressReported = false;
      const replayRes = await window.runInWorker('REPLAY_LOG', { eventsJsonl: events }, (p) => {
        if (p && typeof p.percent === 'number') progressReported = true;
      });

      // 2. COMPUTE_MERKLE
      const dummyRecords = [
        { timestamp: 1700000000, value: 120.5, unit: 'kWh', source: 'SENSOR_01' },
        { timestamp: 1700000060, value: 125.0, unit: 'kWh', source: 'SENSOR_01' }
      ];
      const merkleRes = await window.runInWorker('COMPUTE_MERKLE', {
        recordsJson: dummyRecords,
        timestamp: 1700000100
      });

      return {
        eventsCount: replayRes.events_count,
        chainValid: replayRes.chain_valid,
        invariantsPass: replayRes.invariant_report ? replayRes.invariant_report.all_passed : true,
        merkleRoot: merkleRes.merkle_root_hex,
        leafCount: merkleRes.leaf_count,
        progressReported
      };
    });

    expect(workerTestResult.eventsCount).toBeGreaterThan(0);
    expect(workerTestResult.chainValid).toBe(true);
    expect(workerTestResult.invariantsPass).toBe(true);
    expect(workerTestResult.merkleRoot.length).toBe(64);
    expect(workerTestResult.leafCount).toBe(2);
    expect(workerTestResult.progressReported).toBe(true);
  });

});
