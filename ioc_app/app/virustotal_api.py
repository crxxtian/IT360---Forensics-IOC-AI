import requests
import time

class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3/"
    TIMEOUT = 10
    RETRIES = 2
    DEBUG = False  # Set to True for console logging

    def __init__(self, api_key):
        if not api_key:
            raise ValueError("Missing VirusTotal API key. Make sure it's set in your .env file.")
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def scan_hash(self, file_hash):
        url = f"{self.BASE_URL}files/{file_hash}"
        return self._get(url)

    def scan_ip(self, ip_address):
        url = f"{self.BASE_URL}ip_addresses/{ip_address}"
        return self._get(url)

    def scan_url(self, url_to_scan):
        submit_url = f"{self.BASE_URL}urls"
        data = {"url": url_to_scan}
        response = self._post(submit_url, data)
        if response and "data" in response:
            analysis_id = response["data"].get("id", "")
            return self.get_url_analysis(analysis_id)
        return {"error": "Failed to submit URL for scanning", "details": response}

    def get_url_analysis(self, analysis_id):
        url = f"{self.BASE_URL}analyses/{analysis_id}"
        return self._get(url)

    def _get(self, url):
        for attempt in range(self.RETRIES + 1):
            try:
                if self.DEBUG:
                    print(f"[VT-GET] {url}")
                response = requests.get(url, headers=self.headers, timeout=self.TIMEOUT)
                return self._handle_response(response)
            except requests.RequestException as e:
                if attempt == self.RETRIES:
                    return {"error": "GET request failed", "details": str(e)}
                time.sleep(1)

    def _post(self, url, data):
        for attempt in range(self.RETRIES + 1):
            try:
                if self.DEBUG:
                    print(f"[VT-POST] {url} | Payload: {data}")
                response = requests.post(url, headers=self.headers, data=data, timeout=self.TIMEOUT)
                return self._handle_response(response)
            except requests.RequestException as e:
                if attempt == self.RETRIES:
                    return {"error": "POST request failed", "details": str(e)}
                time.sleep(1)

    def _handle_response(self, response):
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return {"error": "Invalid JSON in response", "raw": response.text}
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later.", "status": 429}
        else:
            return {
                "error": f"Request failed with status code {response.status_code}",
                "details": response.text
            }
