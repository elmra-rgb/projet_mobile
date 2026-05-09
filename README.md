<div align="center">
  <h1>🛡️ Privacy Posture Analyzer</h1>
  <p><strong>A Profile-Based Privacy Auditing Tool for Android APK Files</strong></p>
  
  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
  [![Flask](https://img.shields.io/badge/Flask-3.0.0-lightgrey?logo=flask)](https://flask.palletsprojects.com/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Gemini AI](https://img.shields.io/badge/AI-Google_Gemini-purple?logo=google)](https://deepmind.google/technologies/gemini/)
</div>

---

## 📖 Overview

**Privacy Posture Analyzer** is an open-source, Flask-based web application designed for automated privacy auditing of Android applications (APK files). It bridges the gap between raw static analysis and actionable privacy intelligence. 

By selecting a specific application profile (e.g., Education, Health, E-commerce, Gaming, Social), the tool contextually evaluates Android permissions, detects embedded third-party trackers, and generates a comprehensive compliance report inspired by GDPR and COPPA principles.

### ✨ Key Features

- 🔍 **Static Analysis via Androguard**: Extracts Android Manifest permissions and scans DEX bytecode for known tracker signatures.
- 🎯 **Contextual Permission Classification**: Evaluates permissions as *Normal*, *Sensitive*, *Dangerous*, or *Excessive* based on the app's selected profile.
- 🕵️‍♂️ **Tracker & Secret Detection**: Identifies over 44+ SDKs (Advertising, Analytics, Attribution, Crash reporting, etc.) and hardcoded secrets (API keys, IP addresses, Suspicious URLs).
- 📊 **Weighted Privacy Score**: Computes an automated, weighted privacy score (0–100) and displays a 6-axis Radar Chart against an ideal profile.
- 📋 **Compliance Checklists**: Domain-specific heuristics verifying minimum data collection principles.
- 🤖 **AI-Powered Enrichment (Optional)**: Integrates **Google Gemini 2.0 Flash** to provide contextual, natural-language privacy assessments and personalized minimization recommendations.

---

## 🏗️ Software Architecture

The application follows a modular layered architecture:

1. **Web Layer (`app.py`)**: Handles secure file upload, extension/magic byte validation, and response rendering. Uploaded APKs are strictly analyzed locally and deleted immediately after processing.
2. **Static Analysis Engine (`analyzer.py`)**: Powered by Androguard. Scans classes against a curated tracker database and extracts permissions.
3. **Heuristic Engine (`ai_analysis.py`)**: A deterministic classification system applying penalty weights, calculating scores, and generating profile-aware checklists.
4. **AI Enrichment Module (`gemini_ai.py`)**: Constructs structured prompts from heuristic results and retrieves qualitative analysis from Google Gemini.

---

## 🚀 Installation & Local Execution

### 1. Clone the repository

```bash
git clone https://github.com/elmra-rgb/projet_mobile.git
cd projet_mobile
```

### 2. Create a virtual environment (Recommended)

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Google Gemini API (Optional but recommended)

To enable AI-powered analysis and recommendations, set up your Gemini API key:

```bash
# macOS / Linux
export GEMINI_API_KEY="your_api_key_here"

# Windows (Command Prompt)
set GEMINI_API_KEY="your_api_key_here"
```
*(If left unconfigured, the tool will gracefully default to its deterministic heuristic engine).*

### 5. Launch the Application

```bash
python app.py
```
Access the dashboard via your browser at 👉 **http://127.0.0.1:5001**

---

## 📚 Academic Context & Validation
This software was developed and documented for publication in **SoftwareX**. The underlying static analysis methodology has been validated against industry-standard tools such as Exodus Privacy, demonstrating high accuracy in tracker and permission detection. 

**Corresponding Author / Developer:** Rania Elhezzam (rania.elhezzam@emsi.ma)  
**Supervised by:** Prof. Mohamed Lachgar  
**Institution:** École Marocaine Des Sciences De L'Ingénieur (EMSI), Cybersecurity, Infrastructure and Networks Engineering Department, Morocco.

---

## 📄 License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.
