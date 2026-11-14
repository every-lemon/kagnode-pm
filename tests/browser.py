#!/usr/bin/env python3
"""Actual controller browser journeys with fictional data; no native apply or external requests."""

import asyncio
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
from urllib.request import urlopen
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def journey(browser, origin, password, width):
    context = await browser.new_context(viewport={"width": width, "height": 900})
    page = await context.new_page()
    errors, external = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on(
        "request",
        lambda r: external.append(r.url)
        if not r.url.startswith(origin + "/") and not r.url.startswith("data:")
        else None,
    )
    await page.goto(origin + "/login")
    assert await page.locator(".kn-core-login-card").count() == 1
    assert await page.locator(".sidebar,.topbar,footer").count() == 0
    await page.wait_for_function(
        "() => getComputedStyle(document.querySelector('.kn-core-login-card')).opacity === '1'"
    )
    assert await page.evaluate("getComputedStyle(document.body).margin === '0px'")
    artifacts = os.environ.get("KAGNODE_QA_ARTIFACTS")
    if artifacts and width in (390, 1440):
        Path(artifacts).mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(Path(artifacts) / f"pm-login-{width}.png"))
    await page.locator("input[name=email]").fill("owner@fixture.invalid")
    continue_button = page.get_by_role("button", name="Continue", exact=True)
    if await continue_button.count():
        await continue_button.click()
    await page.locator("input[name=password]").fill(password)
    async with page.expect_navigation():
        await page.get_by_role("button", name="Sign in", exact=True).click()
    try:
        await page.wait_for_function(
            "() => document.querySelector('#page-content .cards')", timeout=10000
        )
    except Exception:
        print(
            json.dumps(
                {
                    "failure_path": page.url.split("?", 1)[0],
                    "title": await page.title(),
                    "errors": errors,
                    "body": (await page.locator("body").inner_text())[:1800],
                }
            ),
            flush=True,
        )
        raise
    assert not errors, errors
    assert await page.evaluate(
        "() => document.documentElement.scrollWidth <= innerWidth + 1"
    )
    assert await page.locator("[data-sidebar-toggle]").count() == 0, (
        "Legacy blank toggle remains"
    )
    assert await page.locator(".kn-core-sidebar-toggle").count() == 1
    if width >= 1024:
        for _ in range(4):
            await page.locator(".kn-core-sidebar-toggle").click()
            await page.mouse.move(1000, 200)
            await page.locator("#main").focus()
            await page.wait_for_timeout(300)
            assert await page.evaluate(
                "document.querySelector('.workspace').getBoundingClientRect().left >= document.querySelector('.sidebar').getBoundingClientRect().width - 1"
            )
    else:
        assert await page.evaluate(
            "document.querySelector('.topbar > div').getBoundingClientRect().left >= document.querySelector('.kn-core-mobile-toggle').getBoundingClientRect().right + 8"
        )
        await page.get_by_role("button", name="Open navigation", exact=True).click()
        await page.keyboard.press("Escape")
        await page.wait_for_function("document.querySelector('.sidebar').inert")
    for route in [
        "servers",
        "reverse-proxies",
        "streams",
        "forward-proxies",
        "certificates",
        "packages",
        "jobs",
        "audit",
        "account",
        "discovery",
        "search",
    ]:
        await page.goto(origin + "/" + route)
        await page.wait_for_function(
            "() => !document.querySelector('#page-content')?.textContent.startsWith('Loading ')"
        )
        assert await page.locator("h1").count() == 1, route
        assert await page.evaluate(
            "() => document.documentElement.scrollWidth <= innerWidth + 1"
        ), route
    await page.goto(origin + "/certificates")
    await page.get_by_role("button", name="Upload certificate", exact=True).click()
    assert await page.locator("dialog[open] input[name=private_ca]").count() == 1
    assert await page.evaluate(
        "() => document.documentElement.scrollWidth <= innerWidth + 1"
    )
    await page.keyboard.press("Escape")
    await page.goto(origin + "/")
    await page.keyboard.press("Control+k")
    await page.locator("#command-palette").wait_for(state="visible")
    assert await page.locator("#command-palette .kn-core-search-row").count() > 0
    await page.keyboard.press("Escape")
    if artifacts and width in (390, 1440):
        await page.screenshot(path=str(Path(artifacts) / f"pm-overview-{width}.png"))
    await page.goto(origin + "/reverse-proxies")
    await page.get_by_role("button", name="Add proxy", exact=True).click()
    dialog = page.locator("dialog[open]")
    name = "browser-" + str(width) + "-" + secrets.token_hex(3)
    await dialog.locator("input[name=name]").fill(name)
    await dialog.locator("textarea[name=domains]").fill(name + ".example.com")
    await dialog.locator("textarea[name=upstreams]").fill("http://127.0.0.1:8080")
    await dialog.get_by_role("button", name="Save draft", exact=True).click()
    await page.wait_for_function("() => !document.querySelector('dialog[open]')")
    await page.get_by_role("cell", name=name, exact=True).wait_for()
    bootstrap = json.loads(await page.locator("#session-data").text_content())
    bad = await context.request.post(
        origin + "/api/v1/servers/fixture-server/packages/plans",
        headers={"X-CSRF-Token": "bad", "Origin": origin},
        data={"names": ["bash"], "request_key": secrets.token_hex(16)},
    )
    assert bad.status >= 400
    response = await context.request.get(
        origin + "/api/v1/servers/fixture-server/resources"
    )
    resources = await response.json()
    item = next(r for r in resources if r["name"] == name)
    update = {
        "id": item["id"],
        "revision": 0,
        "name": name,
        "resource": item["settings"],
    }
    stale = await context.request.post(
        origin + "/api/v1/servers/fixture-server/resources",
        headers={"X-CSRF-Token": bootstrap["csrf"], "Origin": origin},
        data=update,
    )
    assert stale.status == 409
    assert not errors, errors
    assert not external, "Unexpected external browser request"
    await context.close()
    return {
        "width": width,
        "passed": True,
        "actual_login": True,
        "routes": 12,
        "core_login": True,
        "quick_search": True,
        "certificate_upload_dialog": True,
        "draft_create": True,
        "stale_revision": 409,
        "csrf_rejected": True,
        "external_requests": 0,
    }


async def main():
    binary = ROOT / "target/debug/kagnode-proxy-manager"
    engine = os.environ.get("KAGNODE_BROWSER_ENGINE", "chromium")
    password = secrets.token_urlsafe(32)
    report = []
    with tempfile.TemporaryDirectory(prefix="kagnode-proxy-browser-") as directory:
        runtime = Path(directory) / "controller"
        origin = "http://127.0.0.1:" + str(port())
        fleet_port = port()
        init = subprocess.run(
            [
                str(binary),
                "init",
                "--root",
                str(runtime),
                "--email",
                "owner@fixture.invalid",
                "--name",
                "Owner fixture",
                "--public-url",
                origin,
                "--fleet-url",
                "https://127.0.0.1:" + str(fleet_port),
            ],
            input=password,
            text=True,
            capture_output=True,
        )
        assert init.returncode == 0, init.stderr
        with sqlite3.connect(runtime / "proxy.sqlite") as db:
            db.execute(
                "INSERT INTO servers(id,name,seen,summary)VALUES('fixture-server','Fictional offline server',0,'{}')"
            )
        log = open(Path(directory) / "server.log", "wb")
        process = subprocess.Popen(
            [
                str(binary),
                "serve",
                "--root",
                str(runtime),
                "--bind",
                origin.split("//", 1)[1],
                "--fleet-bind",
                "127.0.0.1:" + str(fleet_port),
                "--behind-proxy",
            ],
            stdout=log,
            stderr=log,
        )
        try:
            for _ in range(100):
                try:
                    with urlopen(origin + "/healthz", timeout=1) as r:
                        assert r.status == 200
                    break
                except Exception:
                    if process.poll() is not None:
                        raise RuntimeError("Isolated controller exited during startup")
                    time.sleep(0.1)
            else:
                raise RuntimeError("Controller health timed out")
            async with async_playwright() as p:
                args = {"headless": True}
                custom = os.environ.get("KAGNODE_BROWSER_EXECUTABLE")
                if custom:
                    args["executable_path"] = custom
                if engine == "chromium":
                    args["args"] = ["--no-sandbox"]
                browser = await getattr(p, engine).launch(**args)
                try:
                    for width in [390, 820, 1440]:
                        report.append(await journey(browser, origin, password, width))
                finally:
                    await browser.close()
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
    print(json.dumps({"engine": engine, "cases": report}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
