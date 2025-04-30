# IT360 Forensics IOC Analysis Tool

## Overview
The IT360 Forensics IOC Analysis Tool is our final project for the IT 360 Forensics course. This Python-based application analyzes Indicators of Compromise (IOCs) like file hashes, IP addresses, and URLs using VirusTotal's API and OpenAI's GPT models. It features a sleek PyQt5 GUI for delivering detailed threat reports with AI-powered insights.

## Features
- **VirusTotal Integration**: Real-time threat intelligence for files, IPs, and URLs.
- **AI Analysis**: OpenAI GPT summarizes scan results with risk levels and actionable insights.
- **Interactive GUI**: PyQt5 interface for selecting scan types, entering IOCs, and viewing reports.
- **Threat Classification**: Color-coded verdicts (Safe, Suspicious, Dangerous) with detection details.
- **Cost Estimation**: Transparent OpenAI API cost estimates based on token usage.
- **Clipboard Support**: Copy scan reports for easy sharing.

## Repository Structure
```
ioc_app/
├── app/
│   ├── __init__.py           # Core logic
│   ├── ai_analysis.py        # OpenAI GPT analysis
│   ├── utils.py             # Utility functions
│   └── virustotal_api.py    # VirusTotal API client
├── gui/
│   ├── __init__.py           # GUI package
│   └── main_window.py        # PyQt5 main window
├── main.py                   # App entry point
├── .gitignore                # Git ignore rules
├── README.md                 # Documentation
└── requirements.txt          # Dependencies
```

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/crxxtian/IT360---Forensics-IOC-AI.git
   cd IT360---Forensics-IOC-AI
   ```

2. **Set Up Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys**:
   - Create a `.env` file in the root directory.
   - Add VirusTotal and OpenAI API keys:
     ```plaintext
     VT_API_KEY=your_virustotal_api_key
     OPENAI_API_KEY=your_openai_api_key
     ```
   - Get keys from:
     - [VirusTotal](https://www.virustotal.com/gui/join-us)
     - [OpenAI](https://platform.openai.com/account/api-keys)

## Usage
1. **Run the App**:
   ```bash
   python main.py
   ```

2. **Using the GUI**:
   - Select scan type (File Hash, IP Address, URL).
   - Enter the IOC (e.g., SHA256 hash, IP, or URL).
   - Check "Advanced AI Analysis" for GPT insights (optional).
   - Click "Run Scan" to generate the report.
   - Click "Copy Report" to copy output to clipboard.

## Example Output
```
=== VirusTotal File Scan Report ===
--- Detection Summary ---
Malicious Detections: 8
[SUSPICIOUS] Medium Risk - Proceed with Caution!
--- Threat Classification ---
Suggested Threat Label: trojan
Popular Threat Names:
- Trojan.Win32.Agent (Detected 5 times)
- Mal/Generic-S (Detected 3 times)
VirusTotal Report Link: https://www.virustotal.com/gui/file/<hash>

=== Advanced AI Analysis ===
1. Risk Level: Medium
2. Primary Threat Indicators: Multiple heuristic detections and known threat label
3. Known Malware Patterns: Detected by 8 engines as a trojan variant
4. Confidence Score: 85%
5. One-Sentence Takeaway: Exercise caution; file shows signs of malicious behavior.
```

## Security Notes
- The `.env` file contains sensitive API keys and is ignored by `.gitignore`. Never commit it.
- Treat scan results as sensitive data.
- Keep API keys secure and private.

## Dependencies
Key libraries:
- `PyQt5`: GUI framework
- `openai`: AI analysis
- `requests`: API requests
- `python-dotenv`: Environment variables
- `tiktoken`: Token estimation
- Full list in `requirements.txt`.

## Acknowledgments
- IT 360 Forensics course instructors and team.
- [VirusTotal](https://www.virustotal.com/) for API support.
- [OpenAI](https://openai.com/) for AI capabilities.

---

*Built for IT360 Forensics Final Project*