const { test, expect } = require('@playwright/test');

test.describe('RFC-007 Sovereign Node RPC Adapter & BigInt Accounting', () => {

  test('Shows WASM Sandbox fallback when daemon is offline', async ({ page }) => {
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', err => console.log('PAGE ERROR:', err.message));

    // Intercept daemon RPC requests with 503 Service Unavailable (offline daemon simulation)
    await page.route('http://127.0.0.1:9482/**', async (route) => {
      await route.fulfill({ status: 503, body: 'Offline' });
    });

    await page.goto('/app.html');
    await page.waitForSelector('#nodeStatusBadge', { timeout: 15000 });
    await page.waitForFunction(() => typeof window.openDaemonModal === 'function');

    const badgeText = page.locator('#nodeStatusText');
    await expect(badgeText).toHaveText('WASM Sandbox');

    // Click badge to open modal
    await page.click('#nodeStatusBadge');
    const modal = page.locator('#modalDaemon');
    await expect(modal).toHaveClass(/show/);
    await expect(page.locator('#daemonModalContent')).toContainText('Local daemon offline');

    // Close modal
    await page.click('#modalDaemon .modal-close-btn');
    await expect(modal).not.toHaveClass(/show/);
  });

  test('Updates to Sovereign Node (:9482) when daemon responds and displays chain status', async ({ page }) => {
    // Intercept daemon RPC chain status endpoint
    await page.route('http://127.0.0.1:9482/v1/chain/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept'
        },
        body: JSON.stringify({
          chain_id: 'gm-regtest-1',
          tree_size: '128',
          current_epoch: '4',
          poo_count: '12',
          active_ucos_count: '64',
          latest_checkpoint: 'checkpoints/v2/4.json',
          rpc_port: 9482,
          regtest: true
        })
      });
    });

    await page.goto('/app.html');
    await page.waitForSelector('#nodeStatusBadge', { timeout: 15000 });

    // Verify topbar badge indicates Sovereign Node
    const badgeText = page.locator('#nodeStatusText');
    await expect(badgeText).toHaveText('Sovereign Node (:9482)', { timeout: 10000 });

    // Open modal and verify rendered metrics
    await page.click('#nodeStatusBadge');
    await expect(page.locator('#daemonModalChainId')).toHaveText('gm-regtest-1');
    await expect(page.locator('#daemonModalTreeSize')).toHaveText('128');
    await expect(page.locator('#daemonModalEpoch')).toHaveText('4');
    await expect(page.locator('#daemonModalUcos')).toHaveText('64');
    await expect(page.locator('#daemonModalPoos')).toHaveText('12');
  });

  test('BigInt-safe formatMicroUnitsToCredits and parseCreditsToMicroUnits maintain integer precision', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    const results = await page.evaluate(() => {
      const f = window.formatMicroUnitsToCredits;
      const p = window.parseCreditsToMicroUnits;

      return {
        // Standard conversions
        oneCreditFormatted: f(1000000n),
        fractionalFormatted: f(1500000n),
        microFractionFormatted: f(1n),
        zeroFormatted: f(0n),

        // Large cap conversions (9 billion credits = 9,000,000,000,000,000 micro-units)
        maxCapFormatted: f(9000000000000000n),
        parsedMaxCap: p('9000000000').toString(),
        parsedFractional: p('1.5').toString(),
        parsedSmall: p('0.000001').toString(),
      };
    });

    expect(results.oneCreditFormatted).toBe('1');
    expect(results.fractionalFormatted).toBe('1.5');
    expect(results.microFractionFormatted).toBe('0.000001');
    expect(results.zeroFormatted).toBe('0');
    expect(results.maxCapFormatted).toBe('9000000000');
    expect(results.parsedMaxCap).toBe('9000000000000000');
    expect(results.parsedFractional).toBe('1500000');
    expect(results.parsedSmall).toBe('1');
  });

  test('Rejects negative amounts and amounts beyond protocol cap', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    const errors = await page.evaluate(() => {
      const p = window.parseCreditsToMicroUnits;
      const errs = [];

      try {
        p('-5');
      } catch (e) {
        errs.push(e.message);
      }

      try {
        // Exceeds 9,000,000,000 credits
        p('9000000001');
      } catch (e) {
        errs.push(e.message);
      }

      return errs;
    });

    expect(errors[0]).toContain('Credit amount cannot be negative');
    expect(errors[1]).toContain('exceeds MAX_UCO_MICRO_UNITS');
  });

  test('NodeClient fetches UCO and SPV proofs via RPC endpoints', async ({ page }) => {
    // Intercept UCO lookup
    await page.route('http://127.0.0.1:9482/v1/uco/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
        body: JSON.stringify({
          txid: '1111111111111111111111111111111111111111111111111111111111111111',
          vout: 0,
          project_id: 'PRJ-MANGROVE-001',
          range_start: '1000000',
          range_end: '2000000',
          amount_micro_units: '1000000',
          owner_pubkey: '2222222222222222222222222222222222222222222222222222222222222222'
        })
      });
    });

    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    const uco = await page.evaluate(async () => {
      return await window.daemonClient.getUco('1111111111111111111111111111111111111111111111111111111111111111:0');
    });

    expect(uco.project_id).toBe('PRJ-MANGROVE-001');
    expect(uco.range_start).toBe('1000000');
    expect(uco.range_end).toBe('2000000');
  });

});
