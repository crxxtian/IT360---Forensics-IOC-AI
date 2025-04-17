import json
from colorama import Fore, Style
import tiktoken

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
        return f"{Fore.RED}[DANGEROUS] Highly Malicious - Immediate Action Required!{Style.RESET_ALL}"
    elif 5 <= malicious_count < 15:
        return f"{Fore.YELLOW}[SUSPICIOUS] Medium Risk - Proceed with Caution!{Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}[SAFE] Low Risk - Likely Harmless.{Style.RESET_ALL}"

def format_threat_classification(classification_data):
    if not classification_data:
        return "No classification data available."

    output = "\n--- Threat Classification ---\n"
    label = classification_data.get("suggested_threat_label")
    if label:
        output += f"Suggested Threat Label: {label}\n"

    names = classification_data.get("popular_threat_name", [])
    if names:
        output += "Popular Threat Names:\n"
        for threat in names:
            output += f"- {threat.get('value')} (Detected {threat.get('count')} times)\n"

    categories = classification_data.get("popular_threat_category", [])
    if categories:
        output += "Threat Categories:\n"
        for category in categories:
            output += f"- {category.get('value')} (Detected {category.get('count')} times)\n"

    return output

def format_virus_total_response(response, scan_type):
    if "data" not in response:
        return f"{Fore.RED}Invalid or missing data in response.{Style.RESET_ALL}"

    attributes = response["data"].get("attributes", {})
    identifier = response["data"].get("id", "Unknown")
    malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    classification_data = attributes.get('popular_threat_classification', {})
    verdict = get_threat_verdict(malicious_count)
    vt_link = get_virustotal_gui_link(scan_type, identifier)

    return f"""
=== VirusTotal {scan_type} Scan Report ===
--- Detection Summary ---
Malicious Detections: {malicious_count}
{verdict}
{format_threat_classification(classification_data)}

VirusTotal Report Link: {vt_link}
"""

def reduce_scan_data(scan_data, scan_type):
    if "data" not in scan_data:
        return {"error": "No data available"}
    attributes = scan_data["data"].get("attributes", {})
    reduced = {"id": scan_data["data"].get("id", "Unknown")}

    if scan_type == "File":
        reduced.update({
            "meaningful_name": attributes.get("meaningful_name"),
            "size": attributes.get("size"),
            "sha256": attributes.get("sha256"),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "popular_threat_classification": attributes.get("popular_threat_classification", {})
        })
    elif scan_type == "IP":
        reduced.update({
            "country": attributes.get("country"),
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get("last_analysis_stats", {})
        })
    elif scan_type == "URL":
        reduced.update({
            "url": attributes.get("url"),
            "last_analysis_stats": attributes.get("last_analysis_stats", {})
        })
    else:
        reduced.update({"attributes": attributes})
    return reduced

def estimate_openai_cost(scan_data, model="gpt-4"):
    reduced = reduce_scan_data(scan_data, "File")
    enc = tiktoken.encoding_for_model(model)
    input_tokens = len(enc.encode(json.dumps(reduced)))
    output_tokens = 200
    cost = 0
    if model == "gpt-4":
        cost = (input_tokens / 1000 * 0.03) + (output_tokens / 1000 * 0.06)
    elif model == "gpt-3.5-turbo":
        cost = (input_tokens / 1000 * 0.0015) + (output_tokens / 1000 * 0.002)
    return round(cost, 4), input_tokens, output_tokens

def format_chatgpt_analysis(analysis):
    return f"\n=== Advanced AI Analysis ===\n{analysis.strip()}\n======================================\n"
