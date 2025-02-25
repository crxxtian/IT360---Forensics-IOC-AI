import sys
import os
import json
import requests
import openai
from dotenv import load_dotenv
from datetime import datetime, timezone
from PyQt5 import QtWidgets, QtCore

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize OpenAI client
client = openai.OpenAI(api_key=OPENAI_API_KEY)


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


def format_virus_total_response(response, scan_type):
    if "data" not in response:
        return "Invalid or missing data in response."

    attributes = response["data"].get("attributes", {})
    formatted_output = f"=== VirusTotal {scan_type} Scan Report ===\n"

    if scan_type == "File":
        first_submission = datetime.fromtimestamp(
            attributes.get("first_submission_date", 0), tz=timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S')
        formatted_output += (
            f"File Name: {attributes.get('meaningful_name', 'Unknown')}\n"
            f"File Size: {attributes.get('size', 'Unknown')} bytes\n"
            f"SHA256: {attributes.get('sha256', 'Unknown')}\n"
            f"Type: {attributes.get('type_description', 'Unknown')}\n"
            f"First Submission Date: {first_submission}\n\n"
            f"--- Detection Summary ---\n"
            f"Malicious Detections: {attributes.get('last_analysis_stats', {}).get('malicious', 'Unknown')}\n"
            f"Undetected: {attributes.get('last_analysis_stats', {}).get('undetected', 'Unknown')}\n\n"
            f"--- Threat Classification ---\n"
            f"{json.dumps(attributes.get('popular_threat_classification', {}), indent=4)}\n\n"
            f"VirusTotal Report Link: {response['data'].get('links', {}).get('self', 'Unknown')}\n"
        )
    elif scan_type == "IP":
        formatted_output += (
            f"IP Address: {response['data'].get('id', 'Unknown')}\n"
            f"Country: {attributes.get('country', 'Unknown')}\n"
            f"Reputation: {attributes.get('reputation', 'Unknown')}\n\n"
            f"VirusTotal Report Link: {response['data'].get('links', {}).get('self', 'Unknown')}\n"
        )
    elif scan_type == "URL":
        formatted_output += (
            f"URL: {response['data'].get('id', 'Unknown')}\n\n"
            f"VirusTotal Report Link: {response['data'].get('links', {}).get('self', 'Unknown')}\n"
        )
    else:
        formatted_output = "Unknown scan type."
    return formatted_output


def ask_chatgpt(scan_data, scan_type):
    prompt = f"""
You are a cybersecurity expert specializing in threat intelligence and malware analysis.
Below is a VirusTotal scan result for a {scan_type}. 

Your task is to:
- Provide a high-level assessment of the findings.
- Summarize key indicators that contribute to the risk classification.
- Identify notable patterns, if any, based on the analysis.
- Explain why this {scan_type} is detected as malicious or not.
- Compare the findings to known threat intelligence trends.

Strictly focus on objective analysis of the scan results. Do not provide recommendations.

### Scan Data:
{json.dumps(scan_data, indent=4)}

Deliver a clear and structured cybersecurity assessment.
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an expert in cybersecurity and malware analysis."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"


def format_chatgpt_analysis(analysis):
    formatted_output = "=== Advanced Cybersecurity Analysis ===\n"
    formatted_output += analysis.strip() + "\n"
    formatted_output += "======================================\n"
    return formatted_output


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VirusTotal Scanner & Cybersecurity Analysis")
        self.resize(800, 600)

        # Set a dark green background via stylesheet
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

        # Input field
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
        value = self.input_field.text().strip()
        if not value:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a value for scanning.")
            return

        # Determine scan type
        if self.file_radio.isChecked():
            scan_type = "File"
            result = self.vt.scan_hash(value)
        elif self.ip_radio.isChecked():
            scan_type = "IP"
            result = self.vt.scan_ip(value)
        elif self.url_radio.isChecked():
            scan_type = "URL"
            result = self.vt.scan_url(value)
        else:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Invalid scan type selected.")
            return

        report = format_virus_total_response(result, scan_type)
        self.output_area.append(report)

        # Advanced analysis if selected
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
