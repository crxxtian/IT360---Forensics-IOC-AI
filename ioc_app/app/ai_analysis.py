
import os
import json
from dotenv import load_dotenv
from ioc_app.app.utils import reduce_scan_data

load_dotenv()

def ask_chatgpt(scan_data, scan_type, model="gpt-4", test=False):
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

    import openai
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "Error: Missing OPENAI_API_KEY in environment."

    client = openai.OpenAI(api_key=api_key)

    prompt = f"""
You are a cybersecurity expert. Below is a reduced VirusTotal scan result for a {scan_type}. 

Summarize in 5 bullet points:
1. **Risk Level:** (Low, Medium, High, Critical)
2. **Primary Threat Indicators** (Why is it risky?)
3. **Known Malware Patterns** (If applicable)
4. **Confidence Score** (How sure is the classification?)
5. **One-Sentence Takeaway** (e.g., "Avoid opening this file.")

### Reduced Scan Data:
{json.dumps(reduced_data, indent=4)}

Respond in a short, structured format. No extra explanations.
"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert in cybersecurity and malware analysis with decades of experience."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except openai.OpenAIError as e:
        return f"[OpenAI API Error] {str(e)}"
    except Exception as e:
        return f"[General Error] {str(e)}"
