def calculate_risk(
    threat_result,
    forensic_result,
    sender_result,
    ai_result=None
):

    score = 0

    indicators = []


    # --------------------------------
    # 1. Rule-based threat analysis
    # --------------------------------

    content_score = threat_result.get(
        "score",
        0
    )

    score += min(
        content_score,
        50
    )


    # --------------------------------
    # 2. AI phishing analysis
    # --------------------------------

    if ai_result:

        ai_probability = float(
            ai_result.get(
                "phishing_probability",
                0
            )
        )


        # Convert AI probability into
        # a controlled contribution.
        #
        # Maximum AI contribution = 30

        ai_score = (
            ai_probability / 100
        ) * 30


        score += ai_score


        if ai_probability >= 80:

            indicators.append(
                f"AI detected strong phishing characteristics "
                f"({ai_probability:.2f}% probability)"
            )

        elif ai_probability >= 50:

            indicators.append(
                f"AI detected possible phishing characteristics "
                f"({ai_probability:.2f}% probability)"
            )


    # --------------------------------
    # 3. Sender intelligence
    # --------------------------------

    domain_risk = sender_result.get(
        "domain_risk",
        "UNKNOWN"
    )


    if domain_risk == "HIGH":

        score += 20

        indicators.append(
            "High-risk sender domain detected"
        )


    sender_indicators = sender_result.get(
        "indicators",
        []
    )


    if sender_indicators:

        score += 5

        indicators.append(
            "Suspicious sender characteristics detected"
        )


    # --------------------------------
    # 4. SPF
    # --------------------------------

    spf = forensic_result.get(
        "spf",
        "UNKNOWN"
    )


    if spf == "FAIL":

        score += 10

        indicators.append(
            "SPF authentication failed"
        )


    # --------------------------------
    # 5. DKIM
    # --------------------------------

    dkim = forensic_result.get(
        "dkim",
        "UNKNOWN"
    )


    if dkim == "FAIL":

        score += 10

        indicators.append(
            "DKIM authentication failed"
        )


    # --------------------------------
    # 6. DMARC
    # --------------------------------

    dmarc = forensic_result.get(
        "dmarc",
        "UNKNOWN"
    )


    if dmarc == "FAIL":

        score += 15

        indicators.append(
            "DMARC authentication failed"
        )


    # --------------------------------
    # 7. Suspicious URLs
    # --------------------------------

    urls = threat_result.get(
        "urls",
        []
    )


    suspicious_url_count = 0


    for url in urls:

        if url.get("risk") == "SUSPICIOUS":

            suspicious_url_count += 1


    if suspicious_url_count > 0:

        score += min(
            suspicious_url_count * 10,
            20
        )

        indicators.append(
            f"{suspicious_url_count} suspicious URL(s) detected"
        )


    # --------------------------------
    # 8. Received header information
    # --------------------------------

    ip_addresses = forensic_result.get(
        "ip_addresses",
        []
    )


    if len(ip_addresses) > 0:

        indicators.append(
            f"{len(ip_addresses)} source IP address(es) found in headers"
        )


    # --------------------------------
    # 9. Final score
    # --------------------------------

    score = round(
        min(
            score,
            100
        ),
        2
    )


    # --------------------------------
    # 10. Risk classification
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
            indicators

    }