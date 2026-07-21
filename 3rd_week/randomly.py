import re

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "act fast", "within 24 hours",
    "within 2 hours", "limited time", "expire", "suspended", "blocked",
    "last chance", "final notice", "time-sensitive"
]

THREAT_KEYWORDS = [
    "account will be", "permanently blocked", "legal action",
    "your account has been suspended", "unauthorized access",
    "unusual activity", "will be locked", "penalty"
]

MONEY_OR_CREDENTIAL_KEYWORDS = [
    "verify your password", "confirm your password", "bank details",
    "registration fee", "processing fee", "refundable fee",
    "pay to confirm", "enter your pin", "otp", "credit card number",
    "ssn", "aadhar number", "click here to confirm", "claim your prize",
    "you have won", "wire transfer"
]

VAGUE_GREETING_PATTERNS = [
    r"^dear customer", r"^dear user", r"^dear valued", r"^hi,\s*$",
    r"^hello,\s*$", r"^dear sir/madam"
]

SUSPICIOUS_LINK_PATTERNS = [
    r"bit\.ly", r"tinyurl", r"goo\.gl", r"t\.co", r"is\.gd",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"[a-z0-9-]+-[a-z0-9-]*(verify|secure|update|confirm)[a-z0-9-]*\.",
]

BRAND_LOOKALIKE_HINTS = ["bank", "paypal", "amazon", "microsoft", "google", "internshala"]


def find_matches(text, keyword_list):
    text_lower = text.lower()
    return [kw for kw in keyword_list if kw in text_lower]


def find_links(text):
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+)", text, re.IGNORECASE)


def analyze_links(links):
    flagged = []
    for link in links:
        for pattern in SUSPICIOUS_LINK_PATTERNS:
            if re.search(pattern, link, re.IGNORECASE):
                flagged.append(link)
                break
        else:
            for brand in BRAND_LOOKALIKE_HINTS:
                if brand in link.lower() and re.search(r"[0-9]", link.lower().split(brand)[-1][:3]):
                    flagged.append(link)
                    break
    return flagged


def check_vague_greeting(text):
    first_line = text.strip().split("\n")[0].lower()
    for pattern in VAGUE_GREETING_PATTERNS:
        if re.search(pattern, first_line):
            return True
    return False


def analyze_message(text):
    report = {}

    report["urgency_keywords"] = find_matches(text, URGENCY_KEYWORDS)
    report["threat_keywords"] = find_matches(text, THREAT_KEYWORDS)
    report["money_credential_keywords"] = find_matches(text, MONEY_OR_CREDENTIAL_KEYWORDS)
    report["vague_greeting"] = check_vague_greeting(text)

    links = find_links(text)
    report["links_found"] = links
    report["suspicious_links"] = analyze_links(links)

    score = 0
    score += len(report["urgency_keywords"]) * 2
    score += len(report["threat_keywords"]) * 3
    score += len(report["money_credential_keywords"]) * 3
    score += len(report["suspicious_links"]) * 4
    score += 2 if report["vague_greeting"] else 0

    report["risk_score"] = score
    if score >= 10:
        report["risk_level"] = "HIGH — Likely Phishing"
    elif score >= 4:
        report["risk_level"] = "MEDIUM — Suspicious, verify sender"
    else:
        report["risk_level"] = "LOW — No strong phishing indicators"

    return report


def display_report(message_name, text, report):
    print("=" * 60)
    print(f"MESSAGE: {message_name}")
    print("=" * 60)
    print(text.strip())
    print("-" * 60)
    print("RED FLAGS FOUND:")

    if report["urgency_keywords"]:
        print(f"  - Urgency language: {report['urgency_keywords']}")
    if report["threat_keywords"]:
        print(f"  - Threatening language: {report['threat_keywords']}")
    if report["money_credential_keywords"]:
        print(f"  - Money/credential requests: {report['money_credential_keywords']}")
    if report["vague_greeting"]:
        print("  - Vague/generic greeting (no personal name used)")
    if report["suspicious_links"]:
        print(f"  - Suspicious links: {report['suspicious_links']}")
    if report["links_found"] and not report["suspicious_links"]:
        print(f"  - Links found (appear normal): {report['links_found']}")

    if not any([report["urgency_keywords"], report["threat_keywords"],
                report["money_credential_keywords"], report["vague_greeting"],
                report["suspicious_links"]]):
        print("  - None detected")

    print(f"\nRISK SCORE: {report['risk_score']}")
    print(f"RISK LEVEL: {report['risk_level']}")
    print("=" * 60 + "\n")


SAMPLE_MESSAGES = {
    "Sample 1 - Fake Bank Alert": """
Dear Customer,
We detected unusual activity on your account. Your account will be
permanently blocked within 24 hours unless you verify your identity
immediately. Click here to confirm: http://secure-bank0findia.verify-now.co/login
Failure to act will result in permanent loss of access.
""",

    "Sample 2 - Fake Internship Offer": """
Hi,
Based on your resume on our database, you have been shortlisted for a
Work-From-Home Internship paying Rs 25000/month. To confirm your seat,
pay a refundable registration fee within 2 hours here: bit.ly/intern-confirm-payy
Limited seats available, act fast!
""",

    "Sample 3 - Legitimate Password Reset": """
Hi Jay,
We received a request to reset your password for your account. If this
was you, click below to reset it. This link expires in 30 minutes and
can only be used once.
https://accounts.google.com/reset-password?token=xxxx
If you didn't request this, you can ignore this email.
"""
}


def run_demo():
    for name, message in SAMPLE_MESSAGES.items():
        report = analyze_message(message)
        display_report(name, message, report)


def run_custom():
    print("Paste the message text below. Type 'END' on a new line when done:\n")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    text = "\n".join(lines)
    report = analyze_message(text)
    display_report("Custom Message", text, report)


def main():
    print("PHISHING MESSAGE ANALYZER")
    print("1. Run demo on sample messages")
    print("2. Analyze your own message")
    choice = input("Enter choice (1/2): ").strip()

    if choice == "1":
        run_demo()
    elif choice == "2":
        run_custom()
    else:
        print("Invalid choice. Running demo by default.\n")
        run_demo()


if __name__ == "__main__":
    main()