import os
import json
import requests
from dotenv import load_dotenv
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")


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


def format_virus_total_response(response):
    """ Extracts and formats key information from the VirusTotal API response. """
    if "data" not in response:
        return Fore.RED + "Invalid or missing data in response."

    attributes = response["data"]["attributes"]

    first_submission = datetime.utcfromtimestamp(attributes.get("first_submission_date", 0)).strftime(
        '%Y-%m-%d %H:%M:%S')

    output = f"""
    {Fore.CYAN}{Style.BRIGHT}🔍 VirusTotal Scan Report{Style.RESET_ALL}
    {Fore.GREEN}-----------------------------------{Style.RESET_ALL}
    📂 {Fore.YELLOW}File Name:{Style.RESET_ALL} {attributes.get("meaningful_name", "Unknown")}
    📏 {Fore.YELLOW}File Size:{Style.RESET_ALL} {attributes.get("size", "Unknown")} bytes
    🔢 {Fore.YELLOW}SHA256:{Style.RESET_ALL} {attributes.get("sha256")}
    🏷 {Fore.YELLOW}Type:{Style.RESET_ALL} {attributes.get("type_description", "Unknown")}
    🕒 {Fore.YELLOW}First Submission Date:{Style.RESET_ALL} {first_submission}

    {Fore.RED}⚠️ Detection Summary{Style.RESET_ALL}
    {Fore.GREEN}--------------------------{Style.RESET_ALL}
    🚨 {Fore.RED}Malicious Detections:{Style.RESET_ALL} {attributes["last_analysis_stats"]["malicious"]}
    🛡 {Fore.BLUE}Undetected:{Style.RESET_ALL} {attributes["last_analysis_stats"]["undetected"]}

    📊 {Fore.YELLOW}Popular Threat Classification:{Style.RESET_ALL}
    {json.dumps(attributes.get("popular_threat_classification", {}), indent=4)}

    🔗 {Fore.MAGENTA}VirusTotal Report Link:{Style.RESET_ALL}
    {response["data"]["links"]["self"]}
    """
    return output


if __name__ == "__main__":
    vt = VirusTotalAPI(API_KEY)

    # User input for file hash
    file_hash = input(Fore.CYAN + "Enter file hash to scan: " + Style.RESET_ALL).strip()

    # Fetch and display results
    result = vt.scan_hash(file_hash)
    formatted_report = format_virus_total_response(result)
    print(formatted_report)
