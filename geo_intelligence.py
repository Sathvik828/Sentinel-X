import requests


def get_ip_intelligence(ip):

    # Documentation/private IPs don't have useful public geolocation
    private_or_example = (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("127.")
        or ip.startswith("192.0.2.")
        or ip.startswith("198.51.100.")
        or ip.startswith("203.0.113.")
    )

    if private_or_example:

        return {
            "ip": ip,
            "status": "EXAMPLE/PRIVATE",
            "country": "Not available",
            "region": "Not available",
            "city": "Not available",
            "organization": "Not available"
        }


    try:

        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5
        )

        if response.status_code != 200:

            return {
                "ip": ip,
                "status": "LOOKUP_FAILED",
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "organization": "Unknown"
            }


        data = response.json()


        return {

            "ip": ip,

            "status": "FOUND",

            "country":
                data.get(
                    "country_name",
                    "Unknown"
                ),

            "region":
                data.get(
                    "region",
                    "Unknown"
                ),

            "city":
                data.get(
                    "city",
                    "Unknown"
                ),

            "organization":
                data.get(
                    "org",
                    "Unknown"
                )

        }


    except Exception as e:

        return {

            "ip": ip,

            "status": "LOOKUP_ERROR",

            "country": "Unknown",

            "region": "Unknown",

            "city": "Unknown",

            "organization": "Unknown"

        }


def analyze_ips(ip_addresses):

    results = []

    for ip in ip_addresses:

        results.append(
            get_ip_intelligence(ip)
        )

    return results