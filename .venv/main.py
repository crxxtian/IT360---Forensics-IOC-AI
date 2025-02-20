import os
import json
import requests
import openai
from dotenv import load_dotenv
from datetime import datetime, timezone
from colorama import Fore, Style, init

# Initialize Colorama for cross-platform color support
init(autoreset=True)

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
    """Format the VirusTotal API response for readability with Colorama colors."""
    if "data" not in response:
        return f"{Fore.RED}Invalid or missing data in response.{Style.RESET_ALL}"

    attributes = response["data"].get("attributes", {})
    formatted_output = f"\n{Fore.CYAN}=== VirusTotal {scan_type} Scan Report ==={Style.RESET_ALL}\n"

    if scan_type == "File":
        first_submission = datetime.fromtimestamp(
            attributes.get("first_submission_date", 0), tz=timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S')
        formatted_output += f"""
{Fore.YELLOW}File Name:{Style.RESET_ALL} {attributes.get('meaningful_name', 'Unknown')}
{Fore.YELLOW}File Size:{Style.RESET_ALL} {attributes.get('size', 'Unknown')} bytes
{Fore.YELLOW}SHA256:{Style.RESET_ALL} {attributes.get('sha256', 'Unknown')}
{Fore.YELLOW}Type:{Style.RESET_ALL} {attributes.get('type_description', 'Unknown')}
{Fore.YELLOW}First Submission Date:{Style.RESET_ALL} {first_submission}

{Fore.RED}--- Detection Summary ---{Style.RESET_ALL}
{Fore.RED}Malicious Detections:{Style.RESET_ALL} {attributes.get('last_analysis_stats', {}).get('malicious', 'Unknown')}
{Fore.GREEN}Undetected:{Style.RESET_ALL} {attributes.get('last_analysis_stats', {}).get('undetected', 'Unknown')}

{Fore.YELLOW}--- Threat Classification ---{Style.RESET_ALL}
{json.dumps(attributes.get('popular_threat_classification', {}), indent=4)}

{Fore.CYAN}VirusTotal Report Link:{Style.RESET_ALL}
{response['data'].get('links', {}).get('self', 'Unknown')}
"""
    elif scan_type == "IP":
        formatted_output += f"""
{Fore.YELLOW}IP Address:{Style.RESET_ALL} {response['data'].get('id', 'Unknown')}
{Fore.YELLOW}Country:{Style.RESET_ALL} {attributes.get('country', 'Unknown')}
{Fore.YELLOW}Reputation:{Style.RESET_ALL} {attributes.get('reputation', 'Unknown')}

{Fore.CYAN}VirusTotal Report Link:{Style.RESET_ALL}
{response['data'].get('links', {}).get('self', 'Unknown')}
"""
    elif scan_type == "URL":
        formatted_output += f"""
{Fore.YELLOW}URL:{Style.RESET_ALL} {response['data'].get('id', 'Unknown')}

{Fore.CYAN}VirusTotal Report Link:{Style.RESET_ALL}
{response['data'].get('links', {}).get('self', 'Unknown')}
"""
    else:
        formatted_output = f"{Fore.RED}Unknown scan type.{Style.RESET_ALL}"

    return formatted_output

def ask_chatgpt(scan_data, scan_type):
    """Send the scan data to ChatGPT for high-level cybersecurity analysis (no recommendations)."""
    prompt = f"""
You are a cybersecurity expert specializing in threat intelligence and malware analysis.
Below is a VirusTotal scan result for a {scan_type}. 

Your task is to:
- Provide a **high-level** assessment of the findings.
- Summarize key indicators that contribute to the risk classification.
- Identify notable patterns, if any, based on the analysis.
- Explain why this {scan_type} is detected as malicious or not.
- Compare the findings to known threat intelligence trends.

Strictly focus on **objective analysis** of the scan results. **Do not** provide recommendations.

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
    except openai.OpenAIError as e:
        return f"{Fore.RED}OpenAI API Error: {e}{Style.RESET_ALL}"
    except Exception as e:
        return f"{Fore.RED}General Error: {e}{Style.RESET_ALL}"

def format_chatgpt_analysis(analysis):
    """Formats the ChatGPT response into a structured report-style output with Colorama colors."""
    formatted_output = f"\n{Fore.CYAN}=== Advanced Cybersecurity Analysis ==={Style.RESET_ALL}\n"
    formatted_output += f"{Fore.GREEN}{analysis.strip()}{Style.RESET_ALL}"
    formatted_output += f"\n{Fore.CYAN}======================================{Style.RESET_ALL}\n"
    return formatted_output

if __name__ == "__main__":
    vt = VirusTotalAPI(VT_API_KEY)

    print("\nSelect scan type:")
    print("1. File Hash")
    print("2. IP Address")
    print("3. URL")
    choice = input("Enter option (1/2/3): ").strip()

    result = None
    scan_type = ""

    if choice == "1":
        file_hash = input("Enter file hash to scan: ").strip()
        result = vt.scan_hash(file_hash)
        scan_type = "File"
    elif choice == "2":
        ip_address = input("Enter IP address to scan: ").strip()
        result = vt.scan_ip(ip_address)
        scan_type = "IP"
    elif choice == "3":
        url_to_scan = input("Enter URL to scan: ").strip()
        result = vt.scan_url(url_to_scan)
        scan_type = "URL"
    else:
        print(f"{Fore.RED}Invalid choice. Exiting.{Style.RESET_ALL}")
        exit()

    formatted_report = format_virus_total_response(result, scan_type)
    print(formatted_report)

    advanced = input("Would you like advanced analysis from ChatGPT? (Y/n): ").strip().lower()
    if advanced in ("", "y", "yes"):
        analysis = ask_chatgpt(result, scan_type)
        print(format_chatgpt_analysis(analysis))
