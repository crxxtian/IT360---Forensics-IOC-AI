import sys
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from dotenv import load_dotenv
from ioc_app.app.virustotal_api import VirusTotalAPI
from ioc_app.app.utils import estimate_openai_cost, get_virustotal_gui_link
from ioc_app.app.ai_analysis import ask_chatgpt

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")


class AIWorker(QtCore.QThread):
    finished = QtCore.pyqtSignal(str)

    def __init__(self, scan_data, scan_type, parent=None):
        super().__init__(parent)
        self.scan_data = scan_data
        self.scan_type = scan_type

    def run(self):
        result = ask_chatgpt(self.scan_data, self.scan_type)
        self.finished.emit(result)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ VirusTotal & AI Threat Scanner")
        self.resize(920, 680)
        self.setStyleSheet("background-color: #0B1F0B; color: #E0F2E9;")
        self.setWindowIcon(QtGui.QIcon.fromTheme("security"))

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QtWidgets.QLabel("💻 Advanced IOC Threat Analysis")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("font: bold 20pt 'Segoe UI'; color: #7FFF00;")
        layout.addWidget(title)

        scan_box = QtWidgets.QGroupBox("Select Scan Type")
        scan_box.setStyleSheet(
            "QGroupBox { color: #E0F2E9; border: 2px solid #226622; border-radius: 6px; padding: 8px; }"
        )
        scan_layout = QtWidgets.QHBoxLayout()
        self.file_radio = QtWidgets.QRadioButton("File Hash")
        self.ip_radio = QtWidgets.QRadioButton("IP Address")
        self.url_radio = QtWidgets.QRadioButton("URL")
        self.file_radio.setChecked(True)
        for r in (self.file_radio, self.ip_radio, self.url_radio):
            r.setStyleSheet("color: #E0F2E9; font: 10pt 'Segoe UI';")
            scan_layout.addWidget(r)
        scan_box.setLayout(scan_layout)
        layout.addWidget(scan_box)

        self.input_field = QtWidgets.QLineEdit()
        self.input_field.setPlaceholderText("🔎 Enter hash, IP, or URL...")
        self.input_field.setStyleSheet(
            "QLineEdit { background: #103310; border: 2px solid #226622; border-radius: 6px;"
            " padding: 8px; color: #E0F2E9; font: 11pt 'Consolas'; }"
            "QLineEdit:focus { border: 2px solid #7FFF00; }"
        )
        layout.addWidget(self.input_field)

        self.advanced_checkbox = QtWidgets.QCheckBox(
            "💡 Enable Advanced AI Analysis (GPT)"
        )
        self.advanced_checkbox.setStyleSheet("color: #E0F2E9; font: 10pt 'Segoe UI';")
        layout.addWidget(self.advanced_checkbox)

        btn_layout = QtWidgets.QHBoxLayout()
        self.scan_button = QtWidgets.QPushButton("🚀 Run Scan")
        self.copy_button = QtWidgets.QPushButton("📋 Copy Report")
        for btn in (self.scan_button, self.copy_button):
            btn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.scan_button.setStyleSheet(
            "QPushButton { background: #226622; color: #E0F2E9;"
            " border-radius: 6px; padding: 10px; font: bold 11pt 'Segoe UI'; }"
            "QPushButton:hover { background: #33CC33; }"
        )
        self.copy_button.setStyleSheet(
            "QPushButton { background: #0A1A0A; color: #E0F2E9;"
            " border: 1px solid #226622; border-radius: 6px; padding: 8px; }"
            "QPushButton:hover { background: #1E3E1E; }"
        )
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.copy_button)
        layout.addLayout(btn_layout)

        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setMaximum(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            "QProgressBar { border: 1px solid #226622; border-radius: 4px;"
            " background-color: #0D1F0D; color: #7FFF00; text-align: center; }"
            "QProgressBar::chunk { background-color: #33CC33; }"
        )
        layout.addWidget(self.progress_bar)

        self.output_area = QtWidgets.QTextBrowser()
        self.output_area.setOpenExternalLinks(True)
        self.output_area.setStyleSheet(
            "QTextBrowser { background: #0D1F0D; border: 2px solid #226622;"
            " border-radius: 6px; padding: 10px; color: #E0F2E9; font: 10pt 'Courier New'; }"
            "QScrollBar:vertical { background: #0D1F0D; width: 12px; }"
            "QScrollBar::handle:vertical { background: #226622; border-radius: 6px; }"
        )
        layout.addWidget(self.output_area, stretch=1)

        self.status_label = QtWidgets.QLabel("Ready")
        self.status_label.setStyleSheet("color: #A0CFA0; font: 9pt 'Segoe UI';")
        status_bar = QtWidgets.QStatusBar()
        status_bar.addPermanentWidget(self.status_label)
        self.setStatusBar(status_bar)

        try:
            self.vt = VirusTotalAPI(VT_API_KEY)
        except ValueError as e:
            QtWidgets.QMessageBox.critical(self, "Config Error", str(e))
            sys.exit(1)

        self.scan_button.clicked.connect(self.run_scan)
        self.copy_button.clicked.connect(self.copy_output)

    def run_scan(self):
        self.output_area.clear()
        self.status_label.setText("🚧 Running VirusTotal scan...")
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)

        query = self.input_field.text().strip()
        if not query:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a value.")
            self.scan_button.setEnabled(True)
            self.progress_bar.setVisible(False)
            return

        scan_type, result = (
            ("File", self.vt.scan_hash(query))
            if self.file_radio.isChecked()
            else ("IP", self.vt.scan_ip(query))
            if self.ip_radio.isChecked()
            else ("URL", self.vt.scan_url(query))
        )

        data = result.get("data", {})
        attrs = data.get("attributes", {})
        vt_id = data.get("id", "")
        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        label = attrs.get("popular_threat_classification", {}).get(
            "suggested_threat_label", "N/A"
        )
        vt_link = get_virustotal_gui_link(scan_type, vt_id)

        color = (
            "#FF5555"
            if malicious >= 15
            else "#F1C40F"
            if malicious >= 5
            else "#55FF55"
        )
        # Severity badge
        if malicious >= 25:
            sev_html = "🔥 <b>THREAT LEVEL:</b> <span style='color:#FF4C4C;'>CRITICAL</span>"
        elif malicious >= 10:
            sev_html = "⚠️ <b>THREAT LEVEL:</b> <span style='color:#F1C40F;'>HIGH</span>"
        elif malicious >= 3:
            sev_html = "❗ <b>THREAT LEVEL:</b> <span style='color:#FFA500;'>MEDIUM</span>"
        else:
            sev_html = "✅ <b>THREAT LEVEL:</b> <span style='color:#55FF55;'>LOW</span>"

        self.output_area.insertHtml(f"""
            <h2 style="color:#7FFF00;">🧪 VirusTotal Report</h2>
            <ul style="margin-left:20px;">
              <li><b>Detections:</b> {malicious}</li>
              <li><b>Verdict:</b> <span style="color:{color};">{label}</span></li>
            </ul>
            <p style="margin-left:20px;">{sev_html}</p>
            <p><a href="{vt_link}" style="color:#7FFF00;" target="_blank">Open VT Report</a></p>
            <hr style="border:1px solid #226622;">
        """)

        cost, inp, outp = estimate_openai_cost(result)
        self.output_area.insertHtml(f"""
            <p style="color:#A0CFA0;">🧮 <b>Estimated GPT Cost:</b>
            <span style="color:#7FFF00;">${cost}</span>
            (In: {inp}, Out: {outp} tokens)</p>
        """)

        if self.advanced_checkbox.isChecked():
            self.status_label.setText("🤖 Running AI analysis...")
            self.ai_worker = AIWorker(result, scan_type, self)
            self.ai_worker.finished.connect(self.on_ai_done)
            self.ai_worker.start()
        else:
            self.finish_scan()

    def on_ai_done(self, analysis):
        self.progress_bar.setVisible(False)
        lines = [line.strip() for line in analysis.split("\n") if line.strip()]
        icons = ["🛡️", "🚨", "🧬", "🎯", "⚠️"]
        items = []
        for idx, ln in enumerate(lines):
            items.append(f"<li>{icons[idx] if idx < len(icons) else '•'} {ln}</li>")
        self.output_area.insertHtml(f"""
            <hr style="border:1px solid #226622;">
            <h2 style="color:#33CC33;">🤖 AI Threat Summary</h2>
            <ul style="margin-left:20px; color:#E0F2E9;">
              {''.join(items)}
            </ul>
        """)
        self.finish_scan()

    def finish_scan(self):
        self.scan_button.setEnabled(True)
        self.status_label.setText("✅ Scan completed.")
        self.progress_bar.setVisible(False)
        QtCore.QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))

    def copy_output(self):
        QtWidgets.QApplication.clipboard().setText(self.output_area.toPlainText())
        self.status_label.setText("📋 Report copied.")
        QtCore.QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
