import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow

# Load API keys from .env
load_dotenv()

# Optional: Check for required keys before running
missing_keys = []
if not os.getenv("VT_API_KEY"):
    missing_keys.append("VT_API_KEY")
if not os.getenv("OPENAI_API_KEY"):
    missing_keys.append("OPENAI_API_KEY")

if missing_keys:
    print(f"[ERROR] Missing keys in .env file: {', '.join(missing_keys)}")
    sys.exit(1)

# Launch the app
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
