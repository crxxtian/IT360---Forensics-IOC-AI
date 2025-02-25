import os
import json
import requests
import openai
import tiktoken
from dotenv import load_dotenv
from datetime import datetime, timezone
from colorama import Fore, Style, init

# Initialize Colorama for colors
init(autoreset=True)

# Load API keys from the .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize the OpenAI API client
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
    # Returns a quick verdict based on malicious detection count.
    if malicious_count >= 15:
        return f"{Fore.RED}[DANGEROUS] Highly Malicious - Immediate Action Required!{Style.RESET_ALL}"
    elif 5 <= malicious_count < 15:
        return f"{Fore.YELLOW}[SUSPICIOUS] Medium Risk - Proceed with Caution!{Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}[SAFE] Low Risk - Likely Harmless.{Style.RESET_ALL}"


def format_threat_classification(classification_data):
    # Formats VirusTotal threat classification into a structured format.
    if not classification_data:
        return "No classification data available."

    formatted_output = f"\n{Fore.YELLOW}--- Threat Classification ---{Style.RESET_ALL}\n"
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
    # Format the VirusTotal API response for readability with Colorama colors.
    if "data" not in response:
        return f"{Fore.RED}Invalid or missing data in response.{Style.RESET_ALL}"

    attributes = response["data"].get("attributes", {})
    identifier = response["data"].get("id", "Unknown")
    virustotal_link = get_virustotal_gui_link(scan_type, identifier)

    malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    verdict = get_threat_verdict(malicious_count)

    formatted_output = f"""
{Fore.CYAN}=== VirusTotal {scan_type} Scan Report ==={Style.RESET_ALL}
{Fore.RED}--- Detection Summary ---{Style.RESET_ALL}
{Fore.RED}Malicious Detections:{Style.RESET_ALL} {malicious_count}
{verdict}
{format_threat_classification(attributes.get('popular_threat_classification', {}))}

{Fore.CYAN}VirusTotal Report Link:{Style.RESET_ALL} {virustotal_link}
"""
    return formatted_output


def ask_chatgpt(scan_data, scan_type):
    # Short, high-value analysis prompt engineering.
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

Respond in a **short, structured format**. No extra explanations.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an expert in cybersecurity and malware analysis with decades of experience."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except openai.OpenAIError as e:
        return f"{Fore.RED}OpenAI API Error: {e}{Style.RESET_ALL}"
    except Exception as e:
        return f"{Fore.RED}General Error: {e}{Style.RESET_ALL}"


def format_chatgpt_analysis(analysis):
    # Formats the ChatGPT response into a structured report-style output.
    formatted_output = f"\n{Fore.CYAN}=== Advanced AI Analysis ==={Style.RESET_ALL}\n"
    formatted_output += f"{Fore.GREEN}{analysis.strip()}{Style.RESET_ALL}"
    formatted_output += f"\n{Fore.CYAN}======================================{Style.RESET_ALL}\n"
    return formatted_output


def estimate_openai_cost(scan_data, model="gpt-4"):
    # Estimates the cost of running ChatGPT based on the scan data size.
    enc = tiktoken.encoding_for_model(model)
    input_tokens = len(enc.encode(json.dumps(scan_data)))
    output_tokens = 200  # Estimated output length for a short summary

    if model == "gpt-4":
        cost = (input_tokens / 1000 * 0.03) + (output_tokens / 1000 * 0.06)
    elif model == "gpt-3.5-turbo":
        cost = (input_tokens / 1000 * 0.0015) + (output_tokens / 1000 * 0.002)
    else:
        cost = 0

    return round(cost, 4), input_tokens, output_tokens

# main function
if __name__ == "__main__":
    vt = VirusTotalAPI(VT_API_KEY)

    print("\nSelect scan type:")
    print("1. File Hash")
    print("2. IP Address")
    print("3. URL")
    choice = input("Enter option (1/2/3): ").strip()

    scan_type = "File" if choice == "1" else "IP" if choice == "2" else "URL"
    query = input(f"Enter {scan_type.lower()} to scan: ").strip()

    result = (
        vt.scan_hash(query) if scan_type == "File" else
        vt.scan_ip(query) if scan_type == "IP" else
        vt.scan_url(query)
    )

    formatted_report = format_virus_total_response(result, scan_type)
    print(formatted_report)

    estimated_cost, input_tokens, output_tokens = estimate_openai_cost(result, model="gpt-4")
    print(f"\n{Fore.YELLOW}Estimated cost for AI analysis: ${estimated_cost} "
          f"(Input: {input_tokens} tokens, Output: {output_tokens} tokens){Style.RESET_ALL}")

    advanced = input("Would you like advanced analysis from ChatGPT? (Y/n): ").strip().lower()
    if advanced in ("", "y", "yes"):
        analysis = ask_chatgpt(result, scan_type)
        print(format_chatgpt_analysis(analysis))
