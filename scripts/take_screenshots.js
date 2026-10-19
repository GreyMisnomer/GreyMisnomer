const { chromium } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

async function main() {
  const outDir = path.join(__dirname, '../artifacts_screenshots');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  console.log('Navigating to app.html...');
  await page.goto('http://localhost:8080/app.html');
  await page.waitForSelector('#roleSwitcher');
  await page.waitForTimeout(1000);

  // 1. Dashboard screenshot
  await page.screenshot({ path: path.join(outDir, '01_dashboard.png'), fullPage: false });
  console.log('Screenshot 01_dashboard saved');

  // 2. Sovereign Signer view
  await page.click('#nav-signer');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(outDir, '02_signer.png'), fullPage: false });
  console.log('Screenshot 02_signer saved');

  // 3. Key Manager Modal
  await page.click('#btnKeyManager');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(outDir, '03_key_manager_modal.png'), fullPage: false });
  console.log('Screenshot 03_key_manager_modal saved');

  // Close modal
  await page.click('#modalKeyManager .modal-close-btn');
  await page.waitForTimeout(300);

  // 4. Audit & Ledger view
  await page.click('#nav-audit');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(outDir, '04_audit_ledger.png'), fullPage: false });
  console.log('Screenshot 04_audit_ledger saved');

  await browser.close();
  console.log('Done capturing screenshots!');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
