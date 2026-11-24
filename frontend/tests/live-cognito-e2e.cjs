// Run manually against production: node tests/live-cognito-e2e.cjs
// Creates two temporary Cognito users, exercises hosted sign-in and the API,
// then removes both users and the generated DynamoDB records.
const { chromium } = require('playwright');
const { execFileSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const assert = require('node:assert/strict');

const pool = 'us-east-1_7ckpqHwF5';
const region = 'us-east-1';
const site = 'https://vulnguard.buildwithaveeck.com';
const api = 'https://0n159e640h.execute-api.us-east-1.amazonaws.com';
const table = 'VulnGuardAssessments';
const aws = 'C:/Program Files/Amazon/AWSCLIV2/aws.exe';
const createdUsers = [];
const createdAssessments = [];

function callAws(...args) {
  return execFileSync(aws, [...args, '--region', region, '--output', 'json'], { encoding: 'utf8' });
}

function makeUser(label) {
  const email = `qa-${label}-${randomBytes(5).toString('hex')}@example.invalid`;
  const password = `Qa!${randomBytes(20).toString('base64url')}9a`;
  const result = JSON.parse(callAws('cognito-idp', 'admin-create-user', '--user-pool-id', pool,
    '--username', email, '--user-attributes', `Name=email,Value=${email}`, 'Name=email_verified,Value=true',
    '--message-action', 'SUPPRESS'));
  const username = result.User.Username;
  createdUsers.push(username);
  callAws('cognito-idp', 'admin-set-user-password', '--user-pool-id', pool,
    '--username', username, '--password', password, '--permanent');
  return { email, password, username };
}

async function signIn(browser, user) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(site);
  await page.getByRole('button', { name: 'Sign In / Demo Personas' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.locator('input[name="username"]:visible').fill(user.email);
  await page.locator('input[name="password"]:visible').fill(user.password);
  await page.locator('input[name="signInSubmitButton"]:visible').click();
  await page.waitForURL(`${site}/`, { timeout: 30000 });
  await page.waitForFunction(() => Boolean(sessionStorage.getItem('vulnguard_auth_session')), { timeout: 15000 });
  const session = await page.evaluate(() => JSON.parse(sessionStorage.getItem('vulnguard_auth_session')));
  assert.equal(session.user.email, user.email);
  assert.equal(session.user.clientType, 'cognito_user');
  return { context, page, token: session.accessToken, idToken: session.idToken, sub: session.user.sub };
}

async function request(context, token, method, path, data) {
  const response = await context.request.fetch(`${api}${path}`, {
    method, headers: { Authorization: `Bearer ${token}` }, data, timeout: 45000,
  });
  const body = await response.json();
  return { status: response.status(), body };
}

async function main() {
  let browser;
  try {
    const userA = makeUser('a');
    const userB = makeUser('b');
    browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
    const a = await signIn(browser, userA);
    const b = await signIn(browser, userB);
    assert.notEqual(a.sub, b.sub);
    console.log('PASS: two real Cognito users completed hosted PKCE sign-in');

    const wrongToken = await request(a.context, 'not-a-jwt', 'GET', '/api/assessments');
    const idToken = await request(a.context, a.idToken, 'GET', '/api/assessments');
    assert.equal(wrongToken.status, 401);
    assert.equal(idToken.status, 401);
    console.log('PASS: malformed and ID tokens cannot access protected routes');

    if (!process.env.SKIP_INDEX_CHECKS) {
      const emptyA = await request(a.context, a.token, 'GET', '/api/user/workspace');
      const emptyB = await request(b.context, b.token, 'GET', '/api/user/workspace');
      assert.equal(emptyA.status, 200, JSON.stringify(emptyA.body));
      assert.equal(emptyB.status, 200, JSON.stringify(emptyB.body));
      assert.equal(emptyA.body.user_id, a.sub);
      assert.equal(emptyB.body.user_id, b.sub);
      console.log('PASS: each user receives an isolated workspace');
    }

    const created = await request(a.context, a.token, 'POST', '/api/analyze', {
      cve_id: 'CVE-2021-44228', asset_criticality: 'HIGH',
      internet_exposure: 'PUBLIC_FACING', simulate_offline: true,
      system_context: 'Temporary production QA assessment',
    });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.id;
    assert.ok(id);
    createdAssessments.push(id);
    assert.equal(created.body.owner_user_id, a.sub);
    console.log('PASS: authenticated analysis persisted under user A');

    if (process.env.LIVE_FEEDS) {
      const live = await request(a.context, a.token, 'POST', '/api/analyze', {
        cve_id: 'CVE-2021-44228', asset_criticality: 'HIGH',
        internet_exposure: 'PUBLIC_FACING', simulate_offline: false,
        system_context: 'Temporary live-feed production QA assessment',
      });
      assert.equal(live.status, 201, JSON.stringify(live.body));
      createdAssessments.push(live.body.id);
      assert.equal(live.body.intelligence.is_simulated, false);
      console.log(`PASS: live analysis completed (NVD=${live.body.intelligence.nvd.status}, EPSS=${live.body.intelligence.epss.status}, KEV=${live.body.intelligence.cisa_kev.status}, model=${live.body.remediation.model_used})`);
    }

    const detailA = await request(a.context, a.token, 'GET', `/api/assessments/${id}`);
    const detailB = await request(b.context, b.token, 'GET', `/api/assessments/${id}`);
    assert.equal(detailA.status, 200);
    assert.equal(detailB.status, 404);
    console.log('PASS: assessment detail enforces tenant isolation');
    if (!process.env.SKIP_INDEX_CHECKS) {
      const historyA = await request(a.context, a.token, 'GET', '/api/assessments');
      const historyB = await request(b.context, b.token, 'GET', '/api/assessments');
      assert.equal(historyA.status, 200, JSON.stringify(historyA.body));
      assert.equal(historyB.status, 200, JSON.stringify(historyB.body));
      assert.ok(historyA.body.some(item => item.id === id));
      assert.ok(!historyB.body.some(item => item.id === id));
      console.log('PASS: history enforces tenant isolation');

      await a.page.reload();
      await a.page.waitForTimeout(2000);
      assert.ok(await a.page.getByText('CVE-2021-44228').count());
      console.log('PASS: production UI reload displays saved history');
    }

    await a.page.getByRole('button', { name: /qa-a-/i }).click();
    await a.page.getByRole('button', { name: 'Sign Out' }).click();
    await a.page.waitForURL(`${site}/`, { timeout: 30000 });
    assert.equal(await a.page.evaluate(() => sessionStorage.getItem('vulnguard_auth_session')), null);
    console.log('PASS: hosted sign-out clears the browser session');
  } finally {
    if (browser) await browser.close();
    for (const id of createdAssessments) {
      try { callAws('dynamodb', 'delete-item', '--table-name', table, '--key', JSON.stringify({ assessment_id: { S: id } })); }
      catch { console.error(`Cleanup failed for assessment ${id}`); }
    }
    for (const username of createdUsers) {
      try { callAws('cognito-idp', 'admin-delete-user', '--user-pool-id', pool, '--username', username); }
      catch { console.error(`Cleanup failed for user ${username}`); }
    }
  }
}

main().catch(error => { console.error(`FAIL: ${error.message}`); process.exitCode = 1; });
