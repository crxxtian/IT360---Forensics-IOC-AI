# IT360 Forensics IOC Analysis Tool

## Overview
This project is a group effort for the IT 360 Forensics course, designed to analyze Indicators of Compromise (IOCs) using VirusTotal's API and OpenAI's GPT models. The tool provides a user-friendly PyQt5 GUI to scan file hashes, IP addresses, or URLs, delivering detailed threat reports and advanced AI-driven analysis.

## Features
- **VirusTotal Integration**: Queries VirusTotal API for real-time threat intelligence on files, IPs, and URLs.
- **AI-Powered Analysis**: Leverages OpenAI's GPT models to summarize scan results with risk levels, threat indicators, and actionable insights.
- **Interactive GUI**: Built with PyQt5, offering a sleek interface to select scan types, input IOCs, and view reports.
- **Threat Classification**: Displays malicious detections, threat labels, and categories with color-coded verdicts (Safe, Suspicious, Dangerous).
- **Cost Estimation**: Estimates OpenAI API usage costs based on token counts for transparency.
- **Copy to Clipboard**: Easily copy scan reports for sharing or documentation.

## Repository Structure
```
ioc_app/
├── app/
│   ├── __init__.py           # Core logic package
│   ├── ai_analysis.py        # OpenAI GPT analysis module
│   ├── utils.py             # Utility functions for formatting and processing
│   └── virustotal_api.py    # VirusTotal API client
├── gui/
│   ├── __init__.py           # GUI package
│   └── main_window.py        # PyQt5 main window implementation
├── main.py                   # Application entry point
├── .gitignore                # Git ignore rules
├── README.md                 # Project documentation
└── requirements.txt          # Python dependencies
```

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/it360-forensics-ioc.git
   cd it360-forensics-ioc
   ```

2. **Set Up a Virtual Environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys**:
   - Create a `.env` file in the project root.
   - Add your VirusTotal and OpenAI API keys:
     ```
     VT_API_KEY=your_virustotal_api_key
     OPENAI_API_KEY=your_openai_api_key
     ```
   - Obtain keys from:
     - [VirusTotal](https://www.virustotal.com/gui/join-us)
     - [OpenAI](https://platform.openai.com/account/api-keys)

## Usage
1. **Run the Application**:
   ```bash
   python main.py
   ```

2. **Using the GUI**:
   - Select a scan type (File Hash, IP Address, or URL).
   - Enter the IOC (e.g., a SHA256 hash, IP, or URL).
   - Enable "Advanced AI Analysis" for GPT-based insights (optional).
   - Click "Run Scan" to generate the report.
   - Use "Copy Report" to copy the output to your clipboard.

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
- The `.env` file contains sensitive API keys and is excluded via `.gitignore`. Never commit this file.
- Handle scan results with care, as they may contain sensitive information.
- Ensure API keys are kept secure and not shared publicly.

## Dependencies
Key libraries include:
- `PyQt5`: For the GUI
- `openai`: For AI analysis
- `requests`: For VirusTotal API calls
- `python-dotenv`: For environment variable management
- `tiktoken`: For token estimation
- See `requirements.txt` for the full list.

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- IT 360 Forensics course instructors and team members.
- [VirusTotal](https://www.virustotal.com/) for their API.
- [OpenAI](https://openai.com/) for advanced AI capabilities.

---

*Built with 💻 by the IT360 Forensics Team*