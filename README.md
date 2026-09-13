# SOAR-lite 🦅
> **Lightweight Security Orchestration and Automated Incident Response Platform**

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Backend-green.svg)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)
![Security](https://img.shields.io/badge/Cybersecurity-Blue%20Team-red.svg)

## 📌 Overview
In modern Security Operations Centers (SOCs), analysts face a critical bottleneck: **alert fatigue**. Manually triaging thousands of daily alerts, extracting Indicators of Compromise (IOCs), and querying external threat intelligence platforms consumes valuable time that should be spent on proactive threat hunting. 

**SOAR-lite** is an open-source, lightweight security automation engine developed to combat this issue. Built with Python and Flask, it ingests raw security logs, automatically extracts IOCs using optimized regex, and enriches them via external Threat Intelligence APIs before presenting them in a clean, deduplicated dashboard.

## 🚀 Core Features
* **Automated IOC Extraction:** Parses raw logs (Sysmon, firewalls) to extract IPs, domains, and file hashes (SHA-256/MD5).
* **Threat Intelligence Enrichment:** Autonomous REST API integrations with **VirusTotal**, **AbuseIPDB**, and **Shodan** for real-time reputation scoring.
* **Alert Deduplication Engine:** Prevents alert fatigue by aggregating identical IOCs within specific time windows instead of spawning duplicate alerts.
* **Role-Based Access Control (RBAC):** Tiered permission boundaries separating Tier 1 Analysts and Incident Responders.
* **Containerized Deployment:** Fully Dockerized for zero-configuration deployment across environments.

## 🏗️ Architecture Stack
* **Backend:** Python / Flask
* **Database:** SQLite (Self-contained for rapid local deployment)
* **Frontend:** HTML / CSS / JS (Chart.js for statistical visualization)
* **Deployment:** Docker & Docker Compose

## 📸 Screenshots
*(Add 2-3 screenshots here showing your Dashboard, an enriched alert, and terminal/Docker running logs)*
* `![Dashboard View](link_to_image)`
* `![Alert Details](link_to_image)`

## ⚙️ Installation & Setup

**1. Clone the repository:**
```bash
git clone [https://github.com/FurkanCetinerr/SOAR-lite.git](https://github.com/FurkanCetinerr/SOAR-lite.git)
cd SOAR-lite
