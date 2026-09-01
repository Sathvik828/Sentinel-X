import re


def make_text(value):

    if isinstance(value, list):
        return " ".join(
            str(item) for item in value
        )

    return str(value or "")


def extract_urls(text):

    pattern = r'https?://[^\s<>"\']+'

    return re.findall(
        pattern,
        text
    )


def analyze_threat(email):

    score = 0

    indicators = []

    subject = make_text(
        email.headers.get(
            "Subject",
            ""
        )
    )

    body = make_text(
        email.text_plain
    )

    sender = make_text(
        email.headers.get(
            "From",
            ""
        )
    )

    full_text = (
        subject + " " + body
    ).lower()


    # --------------------------------
    # 1. Urgent language
    # --------------------------------

    urgent_words = [

        "urgent",
        "immediately",
        "action required",
        "verify now",
        "account suspended",
        "security alert"

    ]


    for word in urgent_words:

        if word in full_text:

            score += 10

            indicators.append(
                f"Urgent language detected: {word}"
            )


    # --------------------------------
    # 2. Credential-related language
    # --------------------------------

    credential_words = [

        "password",
        "login",
        "username",
        "credentials",
        "verify your account",
        "sign in"

    ]


    for word in credential_words:

        if word in full_text:

            score += 15

            indicators.append(
                f"Credential-related language: {word}"
            )


    # --------------------------------
    # 3. URL extraction
    # --------------------------------

    urls = extract_urls(
        subject + " " + body
    )


    if urls:

        score += 10

        indicators.append(
            f"{len(urls)} URL(s) found in email"
        )


    # --------------------------------
    # 4. URL analysis
    # --------------------------------

    suspicious_patterns = [

        "bit.ly",
        "tinyurl",
        "login",
        "verify",
        "secure",
        "account",
        "signin",
        "password"

    ]


    url_analysis = []


    for url in urls:

        reasons = []

        url_lower = url.lower()


        for pattern in suspicious_patterns:

            if pattern in url_lower:

                reasons.append(
                    f"Contains suspicious pattern: {pattern}"
                )


        if reasons:

            score += 15

            indicators.append(
                f"Suspicious URL detected: {url}"
            )

            url_analysis.append({

                "url": url,

                "risk": "SUSPICIOUS",

                "reasons": reasons

            })

        else:

            url_analysis.append({

                "url": url,

                "risk": "LOW",

                "reasons": []

            })


    # --------------------------------
    # 5. Sender domain
    # --------------------------------

    if "@" in sender:

        sender_email = re.search(
            r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',
            sender
        )


        if sender_email:

            domain = (
                sender_email
                .group(0)
                .split("@")[-1]
                .lower()
            )


            suspicious_domains = [

                "mailinator.com",
                "tempmail.com",
                "10minutemail.com",
                "guerrillamail.com",
                "yopmail.com"

            ]


            if domain in suspicious_domains:

                score += 25

                indicators.append(
                    f"Suspicious sender domain: {domain}"
                )


    # --------------------------------
    # Keep score within 100
    # --------------------------------

    score = min(
        score,
        100
    )


    # --------------------------------
    # Risk classification
    # --------------------------------

    if score >= 70:

        risk = "HIGH"

    elif score >= 40:

        risk = "MEDIUM"

    else:

        risk = "LOW"


    return {

        "score":
            score,

        "risk":
            risk,

        "indicators":
            indicators,

        "urls":
            url_analysis

    }