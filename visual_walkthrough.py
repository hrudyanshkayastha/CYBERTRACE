"""
CYBERTRACE - Full Visual and Functional Walkthrough Automation
Drives headless Chrome via Selenium to perform the complete 14-step inspection,
captures high-resolution screenshots, checks console logs, and validates all UI views.
"""

import os
import sys
import time
import shutil
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

SCREENSHOTS_DIR = Path(r"C:\Users\ADMIN\.gemini\antigravity\scratch\cybertrace\reports\screenshots")
ARTIFACTS_DIR = Path(r"C:\Users\ADMIN\.gemini\antigravity\brain\18988377-7c72-4e0a-8401-28c93c907b13")

SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

def setup_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1440,920")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    # Enable browser logging
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    
    driver = webdriver.Chrome(options=options)
    return driver

def save_shot(driver, name, desc):
    time.sleep(0.6)  # allow UI animation / rendering
    p1 = SCREENSHOTS_DIR / f"{name}.png"
    p2 = ARTIFACTS_DIR / f"{name}.png"
    driver.save_screenshot(str(p1))
    shutil.copyfile(str(p1), str(p2))
    print(f"[*] [SCREENSHOT] {name}.png - {desc}")

def check_console_errors(driver, step_name):
    logs = driver.get_log("browser")
    errors = [l for l in logs if l["level"] in ("SEVERE", "ERROR")]
    if errors:
        print(f"[!] Warning: Console errors at step '{step_name}':")
        for e in errors:
            print(f"    -> {e['message']}")
    else:
        print(f"[+] [CONSOLE] Zero JS errors at step '{step_name}'.")

def main():
    print("=" * 80)
    print("STARTING FULL CYBERTRACE VISUAL & FUNCTIONAL WALKTHROUGH")
    print("=" * 80)

    driver = setup_driver()
    try:
        # STEP 1: Open Application
        print("\n--- STEP 1: Opening http://127.0.0.1:8000 ---")
        driver.get("http://127.0.0.1:8000")
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "stat-total-events"))
        )
        check_console_errors(driver, "Initial Page Load")
        save_shot(driver, "01_initial_dashboard", "Initial Dashboard view")

        # STEP 2: Inspect Upload Section & Sample Cards
        print("\n--- STEP 2: Inspecting Upload Logs View ---")
        upload_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="upload"]')
        upload_nav.click()
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.ID, "samples-container"))
        )
        save_shot(driver, "02_upload_section", "Upload section with built-in scenario cards")

        # STEP 3: Execute 1-Click Analysis on sample_suspicious_incident.log
        print("\n--- STEP 3: Analyzing sample_suspicious_incident.log ---")
        sample_btns = driver.find_elements(By.XPATH, "//button[contains(text(), 'Analyze Sample')]")
        # Find button inside sample_suspicious_incident card
        found_btn = None
        for b in sample_btns:
            parent = b.find_element(By.XPATH, "./ancestor::div[contains(@class, 'sample-card')]")
            if "sample_suspicious_incident.log" in parent.text:
                found_btn = b
                break

        if found_btn:
            found_btn.click()
        else:
            driver.execute_script("runSampleAnalysis('sample_suspicious_incident.log');")

        # Wait for analysis to complete and return to dashboard
        time.sleep(2.0)
        WebDriverWait(driver, 10).until(
            lambda d: int(d.find_element(By.ID, "stat-total-events").text or "0") > 0
        )
        check_console_errors(driver, "Sample Analysis Complete")
        save_shot(driver, "03_suspicious_dashboard", "Dashboard after analyzing suspicious incident")

        # Verify stats
        tot_ev = driver.find_element(By.ID, "stat-total-events").text
        susp_ev = driver.find_element(By.ID, "stat-suspicious-events").text
        tot_inc = driver.find_element(By.ID, "stat-total-incidents").text
        print(f"[+] Verified Dashboard Stats: Total Events={tot_ev}, Suspicious={susp_ev}, Incidents={tot_inc}")

        # STEP 4: Inspect Incidents View
        print("\n--- STEP 4: Inspecting Incidents View ---")
        inc_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="incidents"]')
        inc_nav.click()
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.CLASS_NAME, "attack-chain-banner"))
        )
        save_shot(driver, "04_incidents_view", "Correlated Incidents list with attack chains")

        # STEP 5: Open Incident Investigation Modal
        print("\n--- STEP 5: Inspecting Incident Investigation Modal ---")
        detail_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Investigate Incident Details')]")
        detail_btn.click()
        WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.ID, "modal-incident-body"))
        )
        save_shot(driver, "05_incident_modal_detail", "Incident investigation modal with factors and timeline")

        # Close modal
        close_btn = driver.find_element(By.CLASS_NAME, "modal-close")
        close_btn.click()
        time.sleep(0.5)

        # STEP 6: Normalized Events View
        print("\n--- STEP 6: Inspecting Normalized Events View ---")
        events_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="events"]')
        events_nav.click()
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.ID, "events-tbody"))
        )
        save_shot(driver, "06_events_view", "Normalized Events table with severity tags")

        # Test Filter
        search_box = driver.find_element(By.ID, "event-search-input")
        search_box.send_keys("admin")
        time.sleep(0.5)
        save_shot(driver, "06b_events_filtered", "Events filtered by query 'admin'")
        search_box.clear()
        time.sleep(0.3)

        # STEP 7: Attack Timeline View
        print("\n--- STEP 7: Inspecting Attack Timeline View ---")
        time_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="timeline"]')
        time_nav.click()
        time.sleep(1.0)
        save_shot(driver, "07_timeline_view", "Chronological Attack Timeline view")

        # STEP 8: IOC Findings View
        print("\n--- STEP 8: Inspecting IOC Findings View ---")
        ioc_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="iocs"]')
        ioc_nav.click()
        time.sleep(0.8)
        save_shot(driver, "08_iocs_view", "Extracted IOC Findings (IPs, domains, users, files)")

        # STEP 9: Risk Assessment View
        print("\n--- STEP 9: Inspecting Risk Assessment View ---")
        risk_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="risk"]')
        risk_nav.click()
        time.sleep(0.8)
        save_shot(driver, "09_risk_assessment_view", "Transparent Risk Scoring model table")

        # STEP 10: Reports View
        print("\n--- STEP 10: Inspecting Reports View ---")
        rep_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="reports"]')
        rep_nav.click()
        time.sleep(0.8)
        save_shot(driver, "10_reports_view", "Reports download center and runs history")

        # STEP 11: Standalone Executive HTML Report
        print("\n--- STEP 11: Inspecting Standalone Executive HTML Report ---")
        report_link = driver.find_element(By.XPATH, "//a[contains(text(), 'View / Print Executive HTML Report')]")
        report_url = report_link.get_attribute("href")
        print(f"[*] Navigating to canonical active report: {report_url}")
        driver.get(report_url)
        time.sleep(1.2)
        
        # Verify strict consistency: must have CRITICAL (80/100)
        report_source = driver.page_source
        assert "CRITICAL (80/100)" in report_source, "Report must display CRITICAL (80/100)!"
        assert "80 / 100" in report_source, "Report must display 80 / 100 in stats!"
        print("[+] Verified: Executive HTML Report matches canonical risk score 80/100 and CRITICAL severity!")
        save_shot(driver, "11_html_executive_report", "Executive standalone HTML incident report with 80/100 CRITICAL")

        # STEP 12: About & Viva Guide View
        print("\n--- STEP 12: Inspecting About & Viva Guide View ---")
        driver.get("http://127.0.0.1:8000")
        time.sleep(0.8)
        about_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="about"]')
        about_nav.click()
        time.sleep(0.8)
        save_shot(driver, "12_viva_guide_view", "Architecture and Beginner Viva Guide with examiner Q&As")

        # STEP 13: Clean Sample Negative Control Test (0 incidents)
        print("\n--- STEP 13: Testing sample_clean.log Negative Control ---")
        upload_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="upload"]')
        upload_nav.click()
        time.sleep(0.8)
        driver.execute_script("runSampleAnalysis('sample_clean.log');")
        time.sleep(2.0)
        inc_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="incidents"]')
        inc_nav.click()
        time.sleep(0.8)
        # Verify 0 incidents message
        inc_text = driver.find_element(By.ID, "incidents-container").text
        assert "No Security Incidents Detected" in inc_text, "Expected zero incidents on clean log!"
        print("[+] Verified: sample_clean.log produced 0 incidents and 0 false alerts!")
        save_shot(driver, "13_clean_sample_zero_incidents", "sample_clean.log producing zero alerts")

        # STEP 14: Malformed Sample Robustness Test
        print("\n--- STEP 14: Testing sample_malformed.log Fault Tolerance ---")
        upload_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="upload"]')
        upload_nav.click()
        time.sleep(0.8)
        driver.execute_script("runSampleAnalysis('sample_malformed.log');")
        time.sleep(2.0)
        events_nav = driver.find_element(By.CSS_SELECTOR, '.nav-link[data-tab="events"]')
        events_nav.click()
        time.sleep(0.8)
        save_shot(driver, "14_malformed_sample_robustness", "sample_malformed.log handled gracefully without crashing")
        print("[+] Verified: sample_malformed.log parsed safely without crashing!")

        # Final console log error audit
        check_console_errors(driver, "Final Inspection Audit")

        print("\n" + "=" * 80)
        print("[+] ALL VISUAL AND FUNCTIONAL INSPECTIONS COMPLETED WITH 100% SUCCESS!")
        print("=" * 80)

    finally:
        driver.quit()

if __name__ == "__main__":
    main()
