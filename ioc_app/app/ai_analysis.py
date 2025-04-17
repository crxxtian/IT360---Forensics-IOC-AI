import os
import json
from dotenv import load_dotenv
from openai import OpenAI
from ioc_app.app.utils import reduce_scan_data

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def ask_chatgpt(scan_data, scan_type, model="gpt-4", test=False, timeout=15):
    reduced_data = reduce_scan_data(scan_data, scan_type)

    if test:
        return (
            "\n=== AI Analysis (Test Mode) ===\n"
            "1. **Risk Level:** Medium\n"
            "2. **Primary Threat Indicators:** Multiple heuristic detections and known threat label\n"
            "3. **Known Malware Patterns:** Detected by 8 engines as a trojan variant\n"
            "4. **Confidence Score:** 85%\n"
            "5. **One-Sentence Takeaway:** Exercise caution; file shows signs of malicious behavior.\n"
            "======================================\n"
        )

    if not client.api_key:
        return "Error: Missing OPENAI_API_KEY in environment."

    prompt = (
        f"You are a cybersecurity expert. Below is a reduced VirusTotal scan result for a {scan_type}.\n\n"
        "Summarize in 5 bullet points:\n"
        "1. **Risk Level:** (Low, Medium, High, Critical)\n"
        "2. **Primary Threat Indicators** (Why is it risky?)\n"
        "3. **Known Malware Patterns** (If applicable)\n"
        "4. **Confidence Score** (How sure is the classification?)\n"
        "5. **One-Sentence Takeaway** (e.g., \"Avoid opening this file.\")\n\n"
        "### Reduced Scan Data:\n"
        f"{json.dumps(reduced_data, indent=4)}\n\n"
        "Respond in a short, structured format. No extra explanations."
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert in cybersecurity and malware analysis with decades of experience."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            timeout=timeout
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"[OpenAI API Error] {e}"
