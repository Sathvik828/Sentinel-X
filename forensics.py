import re


def make_text(value):

    if isinstance(value, list):
        return " ".join(
            str(item) for item in value
        )

    return str(value or "")


def extract_ip_addresses(received_headers):

    ips = []

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for header in received_headers:

        header_text = make_text(header)

        found_ips = re.findall(
            ip_pattern,
            header_text
        )

        for ip in found_ips:

            if ip not in ips:
                ips.append(ip)

    return ips


def analyze_forensics(email):

    headers = email.headers

    received = headers.get(
        "Received",
        []
    )

    if not isinstance(received, list):

        received = [received]


    ip_addresses = extract_ip_addresses(
        received
    )


    authentication = headers.get(
        "Authentication-Results",
        ""
    )

    authentication_text = make_text(
        authentication
    ).lower()


    if "spf=pass" in authentication_text:
        spf = "PASS"

    elif "spf=fail" in authentication_text:
        spf = "FAIL"

    else:
        spf = "UNKNOWN"


    if "dkim=pass" in authentication_text:
        dkim = "PASS"

    elif "dkim=fail" in authentication_text:
        dkim = "FAIL"

    else:
        dkim = "UNKNOWN"


    if "dmarc=pass" in authentication_text:
        dmarc = "PASS"

    elif "dmarc=fail" in authentication_text:
        dmarc = "FAIL"

    else:
        dmarc = "UNKNOWN"


    return {

        "message_id":
            make_text(
                headers.get(
                    "Message-ID",
                    "Unknown"
                )
            ),

        "received_hops":
            len(received),

        "ip_addresses":
            ip_addresses,

        "spf":
            spf,

        "dkim":
            dkim,

        "dmarc":
            dmarc

    }