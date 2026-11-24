// Playwright renders the built React app. Pytest dispatches API requests to FastAPI.
const assert = require('node:assert/strict');
const path = require('node:path');
const readline = require('node:readline');
const { chromium } = require('playwright');

async function main() {
  const [dist, cve, scenario] = process.argv.slice(2);
  const browser = await chromium.launch({ channel: process.env.QA_BROWSER_CHANNEL || undefined });
  const input = readline.createInterface({ input: process.stdin });
  const waiting = new Map();
  const requests = [];
  let index = 0;
  input.on('line', line => {
    const reply = JSON.parse(line);
    waiting.get(reply.id)(reply);
    waiting.delete(reply.id);
  });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.setDefaultTimeout(12000);
    await page.route('**/*', async route => {
      const req = route.request();
      const url = new URL(req.url());
      if (url.hostname !== 'vulnguard.test') return route.abort();
      if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
        const id = ++index;
        const body = req.postDataJSON();
        if (url.pathname === '/api/analyze') requests.push(body);
        const pending = new Promise(resolve => waiting.set(id, resolve));
        process.stdout.write(JSON.stringify({ id, method: req.method(), path: url.pathname + url.search, body }) + '\n');
        const reply = await pending;
        return route.fulfill({ status: reply.status, json: reply.body });
      }
      const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      return route.fulfill({ path: path.join(dist, file) });
    });
    await page.goto('http://vulnguard.test/', { waitUntil: 'networkidle' });
    assert.equal(requests.length, 0, 'Dashboard mount must not invoke inference');
    if (scenario === 'preset') {
      await page.getByRole('button', { name: new RegExp(cve) }).click();
    } else {
      await page.getByRole('button', { name: 'CVE Analyzer', exact: true }).click();
      await page.getByPlaceholder(/^e\.g\. CVE-/).fill(' ' + cve.toLowerCase() + ' ');
      await page.getByRole('button', { name: 'Analyze Vulnerability' }).click();
    }
    if (scenario === 'malformed') {
      await page.getByText(/Invalid format/).waitFor();
      assert.equal(requests.length, 0);
    } else {
      if (scenario === 'absent') await page.getByText('No published intelligence found for ' + cve + '.').waitFor();
      else {
        await page.getByRole('heading', { name: cve, exact: true }).waitFor();
        if (scenario === 'missingCVSS') await page.getByText('CVSS unavailable', { exact: true }).waitFor();
        if (scenario === 'outage') {
          await page.getByText('Status Unverified', { exact: true }).waitFor();
          await page.getByRole('button', { name: /Assessment History/ }).click();
          await page.getByRole('row').filter({ hasText: cve }).getByText('Unknown', { exact: true }).waitFor();
          await page.getByRole('button', { name: 'Analytics' }).click();
          await page.getByText('Unverified KEV status: 1').waitFor();
        }
        if (scenario === 'absentKEV') await page.getByText('Not listed in active KEV catalog').waitFor();
      }
      assert.equal(requests.length, 1);
      assert.equal(requests[0].cve_id, cve);
      assert.equal(requests[0].simulate_offline, false);
    }
  } finally {
    input.close();
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
