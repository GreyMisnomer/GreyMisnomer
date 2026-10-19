const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

test.describe('RFC-006 Decentralized Multi-Mirror Verification & Gateway Failover', () => {

  test('Public ledger view displays canonical IPFS CID, Archive.org mirror, and equivocation defense', async ({ page }) => {
    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Switch to Auditor and open Audit / Public Ledger view
    await page.selectOption('#roleSwitcher', 'auditor');
    await page.click('#nav-audit');
    await expect(page.locator('#view-audit')).toHaveClass(/active/);

    // Verify Public Ledger Verification badge
    const badge = page.locator('#ledgerVerificationBadge');
    await expect(badge).toContainText('VERIFIED', { timeout: 10000 });

    // Verify Multi-Mirror Status Card elements
    const sourceBadge = page.locator('#mirrorIngestionSourceBadge');
    await expect(sourceBadge).toContainText('Source: Primary Origin');

    const ipfsCidEl = page.locator('#mirrorIpfsEventsCid');
    await expect(ipfsCidEl).toContainText('bafybeidqq');

    const arcLink = page.locator('#mirrorArchiveOrgLink');
    await expect(arcLink).toHaveAttribute('href', /web\.archive\.org/);

    const equivocationStatus = page.locator('#mirrorEquivocationStatus');
    await expect(equivocationStatus).toContainText('No Split-View');
  });

  test('Simulated Origin failure triggers automatic fallback and reports mirror source', async ({ page }) => {
    // Intercept origin events.jsonl to fail (simulate CDN / GitHub outage)
    await page.route('http://localhost:8080/events.jsonl', async (route) => {
      await route.abort('failed');
    });

    // Read canonical events.jsonl to serve from the mock IPFS gateway
    const canonicalEvents = fs.readFileSync(path.join(__dirname, '../../events.jsonl'), 'utf-8');

    // Intercept IPFS public gateway request with CORS enabled
    await page.route('https://dweb.link/ipfs/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/plain',
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS'
        },
        body: canonicalEvents
      });
    });

    await page.goto('/app.html');
    await page.waitForSelector('#roleSwitcher', { timeout: 15000 });

    // Navigate to Audit view
    await page.selectOption('#roleSwitcher', 'auditor');
    await page.click('#nav-audit');

    // Verify it ingested from the IPFS mirror fallback
    const sourceBadge = page.locator('#mirrorIngestionSourceBadge');
    await expect(sourceBadge).toContainText('IPFS Mirror', { timeout: 10000 });

    // Verify WASM replayed the fallback log and verified all 5 events
    const countEl = page.locator('#ledgerEventsCount');
    await expect(countEl).toHaveText('5');

    const badge = page.locator('#ledgerVerificationBadge');
    await expect(badge).toContainText('VERIFIED');
  });

});
