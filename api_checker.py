import os
import time
import requests
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("e7d1544c4d2163f0c46ea765458b8d2fcf50e974bb40a4b533794fb10a3774d8")
EMAIL_SENDER = os.getenv("hanishareddy3056@gmail.com")
EMAIL_PASSWORD = os.getenv("12345678900")
EMAIL_RECEIVER = os.getenv("hanishareddy3056@gmail.com")


def scan_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return {"error": "Failed to submit URL", "verdict": "ERROR"}

    analysis_id = response.json()["data"]["id"]

    # Wait for analysis to complete
    print("Waiting for analysis to complete...")
    time.sleep(15)

    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    ).json()

    if "data" not in result:
        return {"error": "No data returned", "verdict": "ERROR"}

    stats = result["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    is_phishing = malicious > 0

    return {
        "url": url,
        "malicious_count": malicious,
        "harmless_count": harmless,
        "is_phishing": is_phishing,
        "verdict": "PHISHING DETECTED" if is_phishing else "SAFE"
    }


def send_email_alert(url, scan_result):
    if not scan_result.get("is_phishing"):
        return

    subject = "Phishing URL Detected!"
    body = f"""
DeepShield Alert!

A phishing URL was detected:

URL: {url}
Verdict: {scan_result['verdict']}
Malicious Detections: {scan_result['malicious_count']}
Harmless Detections: {scan_result['harmless_count']}

Take action immediately.
    """

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("Alert email sent!")
    except Exception as e:
        print(f"Email failed: {e}")


def check_url(url):
    print(f"\nScanning: {url}")
    result = scan_url_virustotal(url)

    if "error" in result:
        print(f"Error: {result['error']}")
        return result

    print(f"Verdict: {result['verdict']}")
    print(f"Malicious: {result['malicious_count']} | Harmless: {result['harmless_count']}")

    if result.get("is_phishing"):
        send_email_alert(url, result)

    return result


if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    check_url(test_url)