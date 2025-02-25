import sys
import os
import json
import requests
import openai
import tiktoken
from datetime import datetime, timezone
from dotenv import load_dotenv
from PyQt5 import QtWidgets, QtCore

# Optional: Colorama for CLI colors (not used in the GUI, but kept for formatting functions)
from colorama import Fore, Style, init

init(autoreset=True)

# Load API keys from the .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize the OpenAI API client
client = openai.OpenAI(api_key=OPENAI_API_KEY)


# --- VirusTotal API & Utility Functions ---
class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3/"

    def __init__(self, api_key):
        if not api_key:
            raise ValueError("Missing VirusTotal API key. Make sure it's set in your .env file.")
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def scan_hash(self, file_hash):
        url = f"{self.BASE_URL}files/{file_hash}"
        response = requests.get(url, headers=self.headers)
        return response.json() if response.status_code == 200 else {"error": "Failed to retrieve data"}

    def scan_ip(self, ip_address):
        url = f"{self.BASE_URL}ip_addresses/{ip_address}"
        response = requests.get(url, headers=self.headers)
        return response.json() if response.status_code == 200 else {"error": "Failed to retrieve data"}

    def scan_url(self, url_to_scan):
        url = f"{self.BASE_URL}urls"
        data = {"url": url_to_scan}
        response = requests.post(url, headers=self.headers, data=data)
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id", "")
            return self.get_url_analysis(analysis_id)
        return {"error": "Failed to submit URL for scanning"}

    def get_url_analysis(self, analysis_id):
        url = f"{self.BASE_URL}analyses/{analysis_id}"
        response = requests.get(url, headers=self.headers)
        return response.json() if response.status_code == 200 else {"error": "Failed to retrieve URL scan results"}


def get_virustotal_gui_link(scan_type, identifier):
    base_url = "https://www.virustotal.com/gui/"
    if scan_type == "File":
        return f"{base_url}file/{identifier}"
    elif scan_type == "IP":
        return f"{base_url}ip-address/{identifier}"
    elif scan_type == "URL":
        return f"{base_url}url/{identifier}"
    return "Unknown"


def get_threat_verdict(malicious_count):
    if malicious_count >= 15:
        return f"[DANGEROUS] Highly Malicious - Immediate Action Required!"
    elif 5 <= malicious_count < 15:
        return f"[SUSPICIOUS] Medium Risk - Proceed with Caution!"
    else:
        return f"[SAFE] Low Risk - Likely Harmless."


def format_threat_classification(classification_data):
    if not classification_data:
        return "No classification data available."

    formatted_output = "\n--- Threat Classification ---\n"
    if "suggested_threat_label" in classification_data:
        formatted_output += f"Suggested Threat Label: {classification_data['suggested_threat_label']}\n"

    if "popular_threat_name" in classification_data:
        formatted_output += "Popular Threat Names:\n"
        for threat in classification_data["popular_threat_name"]:
            formatted_output += f"- {threat['value']} (Detected {threat['count']} times)\n"

    if "popular_threat_category" in classification_data:
        formatted_output += "Threat Categories:\n"
        for category in classification_data["popular_threat_category"]:
            formatted_output += f"- {category['value']} (Detected {category['count']} times)\n"

    return formatted_output


def format_virus_total_response(response, scan_type):
    if "data" not in response:
        return f"{Fore.RED}Invalid or missing data in response.{Style.RESET_ALL}"

    attributes = response["data"].get("attributes", {})
    identifier = response["data"].get("id", "Unknown")
    virustotal_link = get_virustotal_gui_link(scan_type, identifier)

    malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    verdict = get_threat_verdict(malicious_count)

    formatted_output = f"""
=== VirusTotal {scan_type} Scan Report ===
--- Detection Summary ---
Malicious Detections: {malicious_count}
{verdict}
{format_threat_classification(attributes.get('popular_threat_classification', {}))}

VirusTotal Report Link: {virustotal_link}
"""
    return formatted_output


def ask_chatgpt(scan_data, scan_type):
    prompt = f"""
You are a cybersecurity expert. Below is a VirusTotal scan result for a {scan_type}. 

Summarize in 5 bullet points:
1. **Risk Level:** (Low, Medium, High, Critical)
2. **Primary Threat Indicators** (Why is it risky?)
3. **Known Malware Patterns** (If applicable)
4. **Confidence Score** (How sure is the classification?)
5. **One-Sentence Takeaway** (e.g., "Avoid opening this file.")

### Scan Data:
{json.dumps(scan_data, indent=4)}

Respond in a short, structured format. No extra explanations.
"""
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system",
                 "content": "You are an expert in cybersecurity and malware analysis with decades of experience."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except openai.OpenAIError as e:
        return f"OpenAI API Error: {e}"
    except Exception as e:
        return f"General Error: {e}"


def format_chatgpt_analysis(analysis):
    formatted_output = f"\n=== Advanced AI Analysis ===\n{analysis.strip()}\n======================================\n"
    return formatted_output


def estimate_openai_cost(scan_data, model="gpt-4"):
    enc = tiktoken.encoding_for_model(model)
    input_tokens = len(enc.encode(json.dumps(scan_data)))
    output_tokens = 200  # Estimated output length
    if model == "gpt-4":
        cost = (input_tokens / 1000 * 0.03) + (output_tokens / 1000 * 0.06)
    elif model == "gpt-3.5-turbo":
        cost = (input_tokens / 1000 * 0.0015) + (output_tokens / 1000 * 0.002)
    else:
        cost = 0
    return round(cost, 4), input_tokens, output_tokens


# --- PyQt5 GUI Application ---
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VirusTotal Scanner & Cybersecurity Analysis")
        self.resize(800, 600)
        self.setStyleSheet("background-color: #013220; color: white;")

        # Central widget and layout
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        # Scan type selection (radio buttons)
        scan_type_layout = QtWidgets.QHBoxLayout()
        self.file_radio = QtWidgets.QRadioButton("File Hash")
        self.file_radio.setChecked(True)
        self.ip_radio = QtWidgets.QRadioButton("IP Address")
        self.url_radio = QtWidgets.QRadioButton("URL")
        for radio in [self.file_radio, self.ip_radio, self.url_radio]:
            radio.setStyleSheet("color: white; font: 10pt 'Segoe UI';")
            scan_type_layout.addWidget(radio)
        layout.addLayout(scan_type_layout)

        # Input field for query
        self.input_field = QtWidgets.QLineEdit()
        self.input_field.setPlaceholderText("Enter value for scanning...")
        self.input_field.setStyleSheet("font: 10pt 'Segoe UI'; padding: 5px;")
        layout.addWidget(self.input_field)

        # Advanced analysis checkbox
        self.advanced_checkbox = QtWidgets.QCheckBox("Advanced Analysis (ChatGPT)")
        self.advanced_checkbox.setStyleSheet("color: white; font: 10pt 'Segoe UI';")
        layout.addWidget(self.advanced_checkbox)

        # Scan button
        self.scan_button = QtWidgets.QPushButton("Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                font: 10pt 'Segoe UI';
                background-color: #025f3d;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #03854f;
            }
        """)
        self.scan_button.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_button)

        # Output area (read-only text edit)
        self.output_area = QtWidgets.QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("background-color: #002a00; color: white; font: 10pt 'Courier'; padding: 10px;")
        layout.addWidget(self.output_area, stretch=1)

        # Initialize VirusTotal API instance
        try:
            self.vt = VirusTotalAPI(VT_API_KEY)
        except ValueError as e:
            QtWidgets.QMessageBox.critical(self, "Configuration Error", str(e))
            sys.exit(1)

    def run_scan(self):
        self.output_area.clear()
        query = self.input_field.text().strip()
        if not query:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a value for scanning.")
            return

        # Determine scan type and call appropriate VirusTotal API function
        if self.file_radio.isChecked():
            scan_type = "File"
            result = self.vt.scan_hash(query)
        elif self.ip_radio.isChecked():
            scan_type = "IP"
            result = self.vt.scan_ip(query)
        elif self.url_radio.isChecked():
            scan_type = "URL"
            result = self.vt.scan_url(query)
        else:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Invalid scan type selected.")
            return

        # Format and display the VirusTotal scan report
        report = format_virus_total_response(result, scan_type)
        self.output_area.append(report)

        # Estimate OpenAI cost and display it
        estimated_cost, input_tokens, output_tokens = estimate_openai_cost(result, model="gpt-4")
        cost_info = f"\nEstimated cost for AI analysis: ${estimated_cost} (Input: {input_tokens} tokens, Output: {output_tokens} tokens)\n"
        self.output_area.append(cost_info)

        # If advanced analysis is selected, call ChatGPT and display the result
        if self.advanced_checkbox.isChecked():
            self.output_area.append("\nPerforming advanced analysis...\n")
            analysis = ask_chatgpt(result, scan_type)
            formatted_analysis = format_chatgpt_analysis(analysis)
            self.output_area.append(formatted_analysis)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
