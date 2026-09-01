import re


SUSPICIOUS_DOMAINS = [
    "mailinator.com",
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "yopmail.com"
]


def extract_email_address(sender):

    sender = str(sender or "").strip()

    match = re.search(
        r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',
        sender
    )

    if match:
        return match.group(0)

    return ""


def analyze_sender(sender):

    email_address = extract_email_address(
        sender
    )

    if not email_address:

        return {
            "email": "",
            "username": "Unknown",
            "domain": "Unknown",
            "domain_risk": "UNKNOWN",
            "indicators": []
        }


    username, domain = email_address.split(
        "@",
        1
    )


    indicators = []


    if domain.lower() in SUSPICIOUS_DOMAINS:

        domain_risk = "HIGH"

        indicators.append(
            f"Suspicious or temporary email domain: {domain}"
        )

    else:

        domain_risk = "NORMAL"


    suspicious_username_words = [
        "admin",
        "security",
        "support",
        "verify",
        "account",
        "billing",
        "payment"
    ]


    username_lower = username.lower()


    for word in suspicious_username_words:

        if word in username_lower:

            indicators.append(
                f"Security-sensitive sender name: {username}"
            )

            break


    return {

        "email":
            email_address,

        "username":
            username,

        "domain":
            domain,

        "domain_risk":
            domain_risk,

        "indicators":
            indicators

    }