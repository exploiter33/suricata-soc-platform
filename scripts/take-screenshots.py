#!/usr/bin/env python3
"""Take PNG screenshots of all Grafana SOC dashboards."""

import os, sys, time, json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

BASE_URL = "http://localhost:3000"
EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence")
GRAFANA_USER = "admin"
GRAFANA_PASS = "admin"

DASHBOARDS = {
    "alerts-overview": "d/soc-alerts-overview/soc-e28094-alerts-overview",
    "incident-timeline": "d/soc-incident-timeline/soc-e28094-incident-timeline-and-drill-down",
    "threat-intel": "d/soc-threat-intel/soc-e28094-threat-intelligence-and-ioc-view",
}

options = Options()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--window-size=1920,1080")
options.binary_location = "/usr/bin/chromium"

driver = webdriver.Chrome(options=options)
driver.implicitly_wait(15)

try:
    # Login
    print("[*] Logging into Grafana...")
    driver.get(f"{BASE_URL}/login")
    time.sleep(3)

    user_input = driver.find_element(By.NAME, "user")
    pass_input = driver.find_element(By.NAME, "password")
    user_input.send_keys(GRAFANA_USER)
    pass_input.send_keys(GRAFANA_PASS)
    driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
    time.sleep(5)
    print("[+] Logged in")

    for name, path in DASHBOARDS.items():
        url = f"{BASE_URL}/{path}?from=1631548800&to=1798761600&kiosk"
        outfile = os.path.join(EVIDENCE_DIR, f"{name}.png")

        print(f"[*] Capturing {name}...")
        driver.get(url)
        time.sleep(12)

        driver.save_screenshot(outfile)
        size = os.path.getsize(outfile)
        print(f"[+] Saved {outfile} ({size/1024:.1f} KB)")

    print("\n[✓] All screenshots captured")

finally:
    driver.quit()
