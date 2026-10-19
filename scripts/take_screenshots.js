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

  // 5. Portfolio view with Retired Credit & Proof-of-Offset Certificate
  await page.selectOption('#roleSwitcher', 'developer');
  await page.click('#nav-projects');
  await page.fill('#prj-name', 'Maharashtra Solar Phase-1');
  await page.fill('#prj-id', 'PRJ-SOLAR-001');
  await page.click('button:has-text("Register Project")');
  await page.click('#nav-mrv');
  await page.selectOption('#mrv-project-select', 'PRJ-SOLAR-001');
  await page.click('button:has-text("Seed Demo Dataset")');
  await page.click('button:has-text("Compute Merkle Tree Commitment")');
  await page.selectOption('#roleSwitcher', 'validator');
  await page.click('#nav-verification');
  await page.click('button:has-text("Approve & Issue PoI")');
  await page.selectOption('#roleSwitcher', 'developer');
  await page.click('#nav-projects');
  await page.click('button:has-text("Mint")');
  await page.click('#nav-portfolio');
  await page.waitForTimeout(500);
  await page.click('button:has-text("Execute Retirement")');
  await page.waitForTimeout(800);
  await page.evaluate(() => {
    const el = document.querySelector('.content');
    if (el) el.scrollTop = 9999;
  });
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(outDir, '05_portfolio_poo_certificate.png'), fullPage: false });
  console.log('Screenshot 05_portfolio_poo_certificate saved');

  await browser.close();
  console.log('Done capturing screenshots!');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
