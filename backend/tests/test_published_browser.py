"""Opt in after installing Playwright and a supported Chromium browser."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from backend.core.config import settings
from backend.tests.test_published_cves import UNKNOWN, dynamo, feeds, inference

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
pytestmark = pytest.mark.skipif(os.getenv("QA_BROWSER") != "1", reason="requires Playwright and Chromium")


@pytest.fixture(scope="module")
def browser_build(tmp_path_factory):
    dist = tmp_path_factory.mktemp("vulnguard-browser")
    subprocess.run(["node", "node_modules/vite/bin/vite.js", "build", "--outDir", str(dist)],
                   cwd=FRONTEND, env={**os.environ, "VITE_API_BASE_URL": "http://vulnguard.test"}, check=True)
    return dist


@pytest.mark.parametrize("cve, scenario", [
    ("CVE-2021-44228", "preset"), ("CVE-2023-34362", "preset"), ("CVE-2024-3094", "preset"),
    ("CVE-2024-6387", "absentKEV"), ("CVE-2014-0160", "typed"), (UNKNOWN, "absent"),
    ("CVE-2099-123456789", "absent"), ("CVE-24-6387", "malformed"),
    ("CVE-2026-99221", "missingCVSS"), ("CVE-2024-6387", "outage"),
])
def test_browser(client, browser_build, cve, scenario, feeds, inference, dynamo):
    if scenario == "outage":
        feeds["fail"].add(settings.CISA_KEV_URL)
    cmd = ["node", "tests/published-cve.cjs", str(browser_build), cve, scenario]
    with subprocess.Popen(cmd, cwd=FRONTEND, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          text=True, encoding="utf-8") as browser:
        try:
            for line in browser.stdout:
                message = json.loads(line)
                res = client.request(message["method"], message["path"], json=message["body"])
                reply = {"id": message["id"], "status": res.status_code, "body": res.json()}
                browser.stdin.write(json.dumps(reply) + "\n")
                browser.stdin.flush()
            assert browser.wait(timeout=15) == 0
        finally:
            if browser.poll() is None:
                browser.kill()
