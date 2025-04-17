import sys
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from dotenv import load_dotenv
from ioc_app.app.virustotal_api import VirusTotalAPI
from ioc_app.app.utils import (
    format_virus_total_response,
    estimate_openai_cost,
    format_chatgpt_analysis
)
from ioc_app.app.ai_analysis import ask_chatgpt

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 VirusTotal & AI Threat Scanner")
        self.resize(1000, 750)
        self.setStyleSheet("background-color: #121212; color: white;")
        self.setWindowIcon(QtGui.QIcon.fromTheme("security"))

        # Main layout
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        # Title
        title = QtWidgets.QLabel("💻 Advanced IOC Threat Analysis")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("font: bold 18pt 'Segoe UI'; margin: 12px; color: #03DAC5;")
        layout.addWidget(title)

        # Scan type selector
        scan_type_box = QtWidgets.QGroupBox("Select Scan Type")
        scan_layout = QtWidgets.QHBoxLayout()
        self.file_radio = QtWidgets.QRadioButton("File Hash")
        self.ip_radio = QtWidgets.QRadioButton("IP Address")
        self.url_radio = QtWidgets.QRadioButton("URL")
        self.file_radio.setChecked(True)
        for r in [self.file_radio, self.ip_radio, self.url_radio]:
            r.setStyleSheet("font: 10pt 'Segoe UI';")
            scan_layout.addWidget(r)
        scan_type_box.setLayout(scan_layout)
        layout.addWidget(scan_type_box)

        # Input
        self.input_field = QtWidgets.QLineEdit()
        self.input_field.setPlaceholderText("🔎 Enter hash, IP, or URL...")
        self.input_field.setStyleSheet("font: 11pt 'Consolas'; padding: 6px;")
        layout.addWidget(self.input_field)

        # GPT toggle
        self.advanced_checkbox = QtWidgets.QCheckBox("💡 Enable Advanced AI Analysis (GPT)")
        self.advanced_checkbox.setStyleSheet("font: 10pt 'Segoe UI'; padding: 4px;")
        layout.addWidget(self.advanced_checkbox)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.scan_button = QtWidgets.QPushButton("🚀 Run Scan")
        self.copy_button = QtWidgets.QPushButton("📋 Copy Report")
        self.scan_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.copy_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))

        self.scan_button.setStyleSheet("""
            QPushButton {
                font: bold 11pt 'Segoe UI';
                background-color: #03DAC5;
                color: black;
                border: none;
                border-radius: 8px;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #00BFA6;
            }
        """)
        self.copy_button.setStyleSheet("""
            QPushButton {
                font: 10pt 'Segoe UI';
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #555;
                border-radius: 6px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
        """)

        self.scan_button.clicked.connect(self.run_scan)
        self.copy_button.clicked.connect(self.copy_output)

        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.copy_button)
        layout.addLayout(button_layout)

        # Output display
        self.output_area = QtWidgets.QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("""
            background-color: #1E1E1E;
            color: #CCCCCC;
            font: 10pt 'Courier New';
            padding: 10px;
            border-radius: 8px;
        """)
        layout.addWidget(self.output_area, stretch=1)

        # Status bar
        self.status_label = QtWidgets.QLabel("Ready")
        self.status_label.setStyleSheet("font: 9pt 'Segoe UI'; color: #BBBBBB;")
        self.status = QtWidgets.QStatusBar()
        self.status.addPermanentWidget(self.status_label)
        self.setStatusBar(self.status)

        # VirusTotal setup
        try:
            self.vt = VirusTotalAPI(VT_API_KEY)
        except ValueError as e:
            QtWidgets.QMessageBox.critical(self, "Configuration Error", str(e))
            sys.exit(1)

    def run_scan(self):
        self.output_area.clear()
        self.status_label.setText("🚧 Running scan...")

        query = self.input_field.text().strip()
        if not query:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a value for scanning.")
            return

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
            QtWidgets.QMessageBox.warning(self, "Scan Error", "Invalid scan type selected.")
            return

        # Display VT report
        vt_report = format_virus_total_response(result, scan_type)
        self.output_area.append(f"<h3 style='color:#00BFA6;'>🧪 VirusTotal Report</h3><pre>{vt_report}</pre>")

        # Show estimated cost
        cost, input_tokens, output_tokens = estimate_openai_cost(result)
        self.output_area.append(f"""
        <p style='color:#BBB;'>🧮 <b>Estimated GPT Cost:</b> <span style='color:#03DAC5;'>${cost}</span> 
        (Input: {input_tokens} tokens, Output: {output_tokens} tokens)</p>
        <hr>
        """)

        # Run GPT analysis
        if self.advanced_checkbox.isChecked():
            self.output_area.append("<p style='color:#888;'>🤖 Running GPT-based threat summary...</p>")
            analysis = ask_chatgpt(result, scan_type)
            self.output_area.append(f"<div style='margin-top:10px;'>{format_chatgpt_analysis(analysis)}</div>")

        self.status_label.setText("✅ Scan completed.")
        QtCore.QTimer.singleShot(4000, lambda: self.status_label.setText("Ready"))

    def copy_output(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.output_area.toPlainText())
        self.status_label.setText("📋 Report copied to clipboard.")
        QtCore.QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))
