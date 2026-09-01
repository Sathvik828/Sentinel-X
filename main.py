from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
import mailparser

from threat_detector import analyze_threat
from forensics import analyze_forensics
from geo_intelligence import analyze_ips
from sender_intelligence import analyze_sender
from risk_engine import calculate_risk
from ai_detector import analyze_with_ai


app = FastAPI(
    title="Sentinel-X Email Threat Intelligence"
)


MAX_FILE_SIZE = 10 * 1024 * 1024


@app.get("/", response_class=HTMLResponse)
def home():

    return """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>
Sentinel-X | Email Threat Intelligence
</title>

<style>

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {

    min-height: 100vh;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 20%,
            #172554 0%,
            transparent 35%
        ),
        radial-gradient(
            circle at 85% 80%,
            #3b0764 0%,
            transparent 35%
        ),
        #050816;

    color: #e5e7eb;
}


body::before {

    content: "";

    position: fixed;

    inset: 0;

    background-image:

        linear-gradient(
            rgba(34,211,238,0.035) 1px,
            transparent 1px
        ),

        linear-gradient(
            90deg,
            rgba(34,211,238,0.035) 1px,
            transparent 1px
        );

    background-size: 45px 45px;

    pointer-events: none;
}


.navbar {

    height: 75px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 0 7%;

    border-bottom:
        1px solid
        rgba(148,163,184,0.15);

    background:
        rgba(5,8,22,0.85);
}


.brand {

    display: flex;

    align-items: center;

    gap: 12px;
}


.logo {

    width: 42px;

    height: 42px;

    border-radius: 10px;

    display: flex;

    align-items: center;

    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #06b6d4,
            #7c3aed
        );

    font-size: 22px;

    box-shadow:
        0 0 25px
        rgba(34,211,238,0.3);
}


.brand h2 {

    font-size: 18px;

    letter-spacing: 1px;
}


.brand span {

    display: block;

    color: #64748b;

    font-size: 10px;

    letter-spacing: 2px;
}


.status {

    color: #94a3b8;

    font-size: 13px;
}


.dot {

    display: inline-block;

    width: 9px;

    height: 9px;

    background: #22c55e;

    border-radius: 50%;

    margin-right: 7px;

    box-shadow:
        0 0 12px #22c55e;
}


.main {

    width: 90%;

    max-width: 1000px;

    margin: auto;

    padding: 65px 0;

    text-align: center;
}


.tag {

    display: inline-block;

    padding: 7px 15px;

    border:
        1px solid
        rgba(34,211,238,0.3);

    border-radius: 20px;

    color: #67e8f9;

    font-size: 12px;

    letter-spacing: 1.5px;

    margin-bottom: 20px;
}


h1 {

    font-size: 58px;

    line-height: 1.05;

    margin-bottom: 20px;

    background:
        linear-gradient(
            90deg,
            #e0f2fe,
            #67e8f9,
            #c4b5fd
        );

    -webkit-background-clip: text;

    -webkit-text-fill-color: transparent;
}


.subtitle {

    color: #94a3b8;

    font-size: 17px;

    line-height: 1.7;

    max-width: 680px;

    margin: auto;
}


.upload-card {

    max-width: 680px;

    margin: 45px auto 30px;

    padding: 45px;

    border-radius: 20px;

    border:
        1px solid
        rgba(34,211,238,0.25);

    background:
        rgba(15,23,42,0.75);

    box-shadow:
        0 20px 80px
        rgba(0,0,0,0.4);
}


.upload-icon {

    width: 75px;

    height: 75px;

    margin:
        auto auto 20px;

    display: flex;

    align-items: center;

    justify-content: center;

    border-radius: 18px;

    background:
        rgba(34,211,238,0.08);

    border:
        1px solid
        rgba(34,211,238,0.25);

    font-size: 35px;
}


.upload-card h2 {

    font-size: 24px;

    margin-bottom: 10px;
}


.upload-card p {

    color: #64748b;

    margin-bottom: 25px;
}


.file-input {

    width: 100%;

    padding: 15px;

    border:
        1px dashed
        #334155;

    border-radius: 10px;

    background: #020617;

    color: #94a3b8;
}


.analyze-button {

    margin-top: 22px;

    padding: 14px 32px;

    border: none;

    border-radius: 9px;

    background:
        linear-gradient(
            90deg,
            #0891b2,
            #7c3aed
        );

    color: white;

    font-size: 15px;

    font-weight: bold;

    cursor: pointer;

    transition: 0.25s;
}


.analyze-button:hover {

    transform:
        translateY(-2px);

    box-shadow:
        0 12px 35px
        rgba(34,211,238,0.3);
}


#result {

    max-width: 760px;

    margin: 25px auto;

    padding: 25px;

    border-radius: 15px;

    border:
        1px solid
        rgba(34,211,238,0.2);

    background:
        rgba(15,23,42,0.9);

    display: none;

    text-align: left;
}


.result-title {

    color: #67e8f9;

    margin-bottom: 15px;
}


.result-row {

    padding: 11px 0;

    border-bottom:
        1px solid
        rgba(148,163,184,0.1);

    line-height: 1.5;

    word-break: break-word;
}


.result-label {

    color: #64748b;

    display: inline-block;

    width: 130px;
}


.risk {

    margin-top: 20px;

    padding: 24px;

    border-radius: 12px;

    text-align: center;

    background:
        rgba(124,58,237,0.1);

    border:
        1px solid
        rgba(124,58,237,0.3);
}


.score {

    font-size: 48px;

    font-weight: bold;

    color: #67e8f9;

    margin-bottom: 8px;
}


.risk-high {

    color: #ef4444;

    font-weight: bold;
}


.risk-medium {

    color: #f59e0b;

    font-weight: bold;
}


.risk-low {

    color: #22c55e;

    font-weight: bold;
}


.section {

    margin-top: 28px;
}


.section h3 {

    margin-bottom: 12px;

    color: #cbd5e1;
}


.section ul {

    padding-left: 20px;
}


.section li {

    margin: 10px 0;

    color: #cbd5e1;

    word-break: break-word;
}


.ai-card {

    margin-top: 15px;

    padding: 20px;

    border-radius: 12px;

    background:
        rgba(6,182,212,0.06);

    border:
        1px solid
        rgba(6,182,212,0.25);

    text-align: center;
}


.ai-title {

    color: #67e8f9;

    font-size: 13px;

    letter-spacing: 1px;

    margin-bottom: 12px;
}


.ai-label {

    font-size: 24px;

    font-weight: bold;

    margin-bottom: 8px;
}


.ai-phishing {

    color: #ef4444;
}


.ai-legitimate {

    color: #22c55e;
}


.ai-error {

    color: #f59e0b;
}


.ai-probability {

    color: #cbd5e1;

    font-size: 14px;
}


.auth-grid {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 10px;

    margin-top: 15px;
}


.auth-card {

    padding: 14px;

    text-align: center;

    border-radius: 10px;

    background:
        rgba(2,6,23,0.7);

    border:
        1px solid
        rgba(148,163,184,0.12);
}


.auth-name {

    color: #64748b;

    font-size: 12px;
}


.auth-value {

    margin-top: 6px;

    font-weight: bold;
}


.auth-pass {

    color: #22c55e;
}


.auth-fail {

    color: #ef4444;
}


.auth-unknown {

    color: #f59e0b;
}


.sender-card {

    margin-top: 12px;

    padding: 18px;

    border-radius: 12px;

    background:
        rgba(2,6,23,0.7);

    border:
        1px solid
        rgba(148,163,184,0.12);
}


.sender-email {

    color: #67e8f9;

    font-size: 17px;

    font-weight: bold;

    margin-bottom: 12px;
}


.sender-detail {

    color: #94a3b8;

    line-height: 1.8;

    font-size: 14px;
}


.domain-normal {

    color: #22c55e;

    font-weight: bold;
}


.domain-high {

    color: #ef4444;

    font-weight: bold;
}


.domain-unknown {

    color: #f59e0b;

    font-weight: bold;
}


.ip-card {

    margin-top: 12px;

    padding: 15px;

    border-radius: 10px;

    background:
        rgba(2,6,23,0.7);

    border:
        1px solid
        rgba(148,163,184,0.12);
}


.ip-address {

    color: #67e8f9;

    font-weight: bold;
}


.ip-info {

    margin-top: 8px;

    color: #94a3b8;

    font-size: 13px;

    line-height: 1.7;
}


.features {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 15px;

    max-width: 680px;

    margin: auto;
}


.feature {

    padding: 18px;

    border-radius: 12px;

    border:
        1px solid
        rgba(148,163,184,0.12);

    background:
        rgba(15,23,42,0.5);
}


.feature-icon {

    font-size: 23px;

    margin-bottom: 8px;
}


.feature h3 {

    font-size: 14px;

    margin-bottom: 5px;
}


.feature p {

    color: #64748b;

    font-size: 11px;
}


@media (max-width: 700px) {

    h1 {
        font-size: 40px;
    }

    .status {
        display: none;
    }

    .features {
        grid-template-columns: 1fr;
    }

    .auth-grid {
        grid-template-columns: 1fr;
    }

    .upload-card {
        padding: 30px 20px;
    }

}

</style>

</head>


<body>


<nav class="navbar">

<div class="brand">

<div class="logo">
🛡️
</div>

<div>

<h2>
SENTINEL-X
</h2>

<span>
THREAT INTELLIGENCE
</span>

</div>

</div>


<div class="status">

<span class="dot"></span>

SYSTEM ONLINE

</div>

</nav>


<main class="main">


<div class="tag">
AI-POWERED EMAIL SECURITY
</div>


<h1>

Detect Threats.<br>

Protect Intelligence.

</h1>


<p class="subtitle">

Analyze suspicious emails using
AI phishing detection, sender intelligence,
authentication forensics and IP intelligence.

</p>


<div class="upload-card">


<div class="upload-icon">
📧
</div>


<h2>
Analyze an Email
</h2>


<p>
Upload an email file in .eml format
</p>


<input
class="file-input"
type="file"
id="emailFile"
accept=".eml"
>


<button
class="analyze-button"
onclick="analyzeEmail()"
>

⚡ ANALYZE EMAIL

</button>


</div>


<div id="result">
</div>


<div class="features">


<div class="feature">

<div class="feature-icon">
🤖
</div>

<h3>
AI Detection
</h3>

<p>
Phishing classification
</p>

</div>


<div class="feature">

<div class="feature-icon">
🌍
</div>

<h3>
IP Intelligence
</h3>

<p>
Header source analysis
</p>

</div>


<div class="feature">

<div class="feature-icon">
🔐
</div>

<h3>
Email Forensics
</h3>

<p>
Authentication analysis
</p>

</div>


</div>


</main>


<script>

async function analyzeEmail() {

    const fileInput =
        document.getElementById(
            "emailFile"
        );

    const result =
        document.getElementById(
            "result"
        );


    if (!fileInput.files.length) {

        alert(
            "Please select an .eml file first."
        );

        return;
    }


    const file =
        fileInput.files[0];


    if (
        !file.name
            .toLowerCase()
            .endsWith(".eml")
    ) {

        alert(
            "Only .eml files are supported."
        );

        return;
    }


    if (
        file.size >
        10 * 1024 * 1024
    ) {

        alert(
            "File is too large. Maximum size is 10 MB."
        );

        return;
    }


    const formData =
        new FormData();


    formData.append(
        "file",
        file
    );


    result.style.display =
        "block";


    result.innerHTML =

        "<h3 class='result-title'>" +

        "⏳ Analyzing email with AI..." +

        "</h3>";


    try {

        const response =
            await fetch(
                "/analyze",
                {
                    method: "POST",
                    body: formData
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            result.innerHTML =

                "<h3 class='result-title'>" +

                "❌ Analysis Failed" +

                "</h3>" +

                "<p>" +

                (
                    data.detail ||
                    "Unable to analyze the email."
                ) +

                "</p>";

            return;
        }


        if (data.error) {

            result.innerHTML =

                "<h3 class='result-title'>" +

                "❌ Analysis Error" +

                "</h3>" +

                "<p>" +

                "The email could not be analyzed." +

                "</p>";

            return;
        }


        let riskClass = "";


        if (
            data.risk === "HIGH"
        ) {

            riskClass =
                "risk-high";

        }

        else if (
            data.risk === "MEDIUM"
        ) {

            riskClass =
                "risk-medium";

        }

        else {

            riskClass =
                "risk-low";

        }


        let aiClass =
            "ai-error";


        if (
            data.ai_label === "PHISHING"
        ) {

            aiClass =
                "ai-phishing";

        }

        else if (
            data.ai_label === "LEGITIMATE"
        ) {

            aiClass =
                "ai-legitimate";

        }


        let indicatorHTML =
            "";


        if (
            !data.indicators ||
            data.indicators.length === 0
        ) {

            indicatorHTML =
                "<li>✅ No suspicious indicators detected</li>";

        }

        else {

            data.indicators.forEach(
                function(indicator) {

                    indicatorHTML +=

                        "<li>⚠️ " +

                        indicator +

                        "</li>";

                }
            );

        }


        let urlHTML =
            "";


        if (
            !data.urls ||
            data.urls.length === 0
        ) {

            urlHTML =
                "<li>✅ No URLs detected</li>";

        }

        else {

            data.urls.forEach(
                function(item) {

                    const icon =
                        item.risk ===
                        "SUSPICIOUS"
                        ? "⚠️"
                        : "✅";


                    urlHTML += `

                        <li>

                            ${icon}

                            ${item.url}

                            —

                            ${item.risk}

                        </li>

                    `;

                }
            );

        }


        let ipHTML =
            "";


        if (
            !data.ip_intelligence ||
            data.ip_intelligence.length === 0
        ) {

            ipHTML =

                "<div class='ip-card'>" +

                "ℹ️ No IP addresses found" +

                "</div>";

        }

        else {

            data.ip_intelligence.forEach(
                function(item) {

                    ipHTML += `

                        <div class="ip-card">

                            <div class="ip-address">

                                🌐 ${item.ip}

                            </div>

                            <div class="ip-info">

                                Status:
                                ${item.status}

                                <br>

                                Country:
                                ${item.country}

                                <br>

                                Region:
                                ${item.region}

                                <br>

                                City:
                                ${item.city}

                                <br>

                                Organization:
                                ${item.organization}

                            </div>

                        </div>

                    `;

                }
            );

        }


        function authClass(value) {

            if (
                value === "PASS"
            ) {

                return "auth-pass";

            }


            if (
                value === "FAIL"
            ) {

                return "auth-fail";

            }


            return "auth-unknown";

        }


        let senderIndicatorsHTML =
            "";


        if (
            !data.sender_indicators ||
            data.sender_indicators.length === 0
        ) {

            senderIndicatorsHTML =

                "<li>✅ No sender-specific indicators</li>";

        }

        else {

            data.sender_indicators.forEach(
                function(indicator) {

                    senderIndicatorsHTML +=

                        "<li>⚠️ " +

                        indicator +

                        "</li>";

                }
            );

        }


        let domainClass =
            "domain-normal";


        if (
            data.domain_risk === "HIGH"
        ) {

            domainClass =
                "domain-high";

        }

        else if (
            data.domain_risk === "UNKNOWN"
        ) {

            domainClass =
                "domain-unknown";

        }


        result.innerHTML = `

            <h3 class="result-title">

                📊 Email Threat Analysis

            </h3>


            <div class="result-row">

                <span class="result-label">
                    From
                </span>

                ${data.from}

            </div>


            <div class="result-row">

                <span class="result-label">
                    To
                </span>

                ${data.to}

            </div>


            <div class="result-row">

                <span class="result-label">
                    Subject
                </span>

                ${data.subject}

            </div>


            <div class="result-row">

                <span class="result-label">
                    Date
                </span>

                ${data.date}

            </div>


            <div class="result-row">

                <span class="result-label">
                    Message-ID
                </span>

                ${data.message_id}

            </div>


            <div class="result-row">

                <span class="result-label">
                    URLs
                </span>

                ${data.url_count}

            </div>


            <div class="result-row">

                <span class="result-label">
                    Attachments
                </span>

                ${data.attachment_count}

            </div>


            <div class="risk">

                <div class="score">

                    ${data.score}/100

                </div>


                <div class="${riskClass}">

                    ${data.risk} RISK

                </div>

            </div>


            <div class="section">

                <div class="ai-card">

                    <div class="ai-title">

                        🤖 AI PHISHING DETECTION

                    </div>


                    <div class="ai-label ${aiClass}">

                        ${data.ai_label}

                    </div>


                    <div class="ai-probability">

                        Confidence:

                        <strong>
                            ${data.ai_confidence}%
                        </strong>

                        <br>

                        Phishing Probability:

                        <strong>
                            ${data.ai_phishing_probability}%
                        </strong>

                    </div>

                </div>

            </div>


            <div class="section">

                <h3>
                    👤 Sender Intelligence
                </h3>


                <div class="sender-card">

                    <div class="sender-email">

                        ${data.sender_email}

                    </div>


                    <div class="sender-detail">

                        Username:
                        ${data.sender_username}

                        <br>

                        Domain:
                        ${data.sender_domain}

                        <br>

                        Domain Risk:

                        <span class="${domainClass}">

                            ${data.domain_risk}

                        </span>

                    </div>

                </div>


                <ul style="margin-top:15px;">

                    ${senderIndicatorsHTML}

                </ul>

            </div>


            <div class="section">

                <h3>
                    🔗 URL Analysis
                </h3>

                <ul>

                    ${urlHTML}

                </ul>

            </div>


            <div class="section">

                <h3>
                    🔐 Authentication
                </h3>


                <div class="auth-grid">


                    <div class="auth-card">

                        <div class="auth-name">
                            SPF
                        </div>

                        <div class="
                            auth-value
                            ${authClass(data.spf)}
                        ">

                            ${data.spf}

                        </div>

                    </div>


                    <div class="auth-card">

                        <div class="auth-name">
                            DKIM
                        </div>

                        <div class="
                            auth-value
                            ${authClass(data.dkim)}
                        ">

                            ${data.dkim}

                        </div>

                    </div>


                    <div class="auth-card">

                        <div class="auth-name">
                            DMARC
                        </div>

                        <div class="
                            auth-value
                            ${authClass(data.dmarc)}
                        ">

                            ${data.dmarc}

                        </div>

                    </div>


                </div>

            </div>


            <div class="section">

                <h3>
                    🌐 IP Intelligence
                </h3>


                <p style="
                    color:#64748b;
                    margin-bottom:10px;
                ">

                    Received hops:
                    ${data.received_hops}

                </p>


                ${ipHTML}

            </div>


            <div class="section">

                <h3>
                    🚨 Threat Indicators
                </h3>


                <ul>

                    ${indicatorHTML}

                </ul>

            </div>

        `;

    }


    catch (error) {

        result.innerHTML =

            "<h3 class='result-title'>" +

            "❌ Connection Error" +

            "</h3>" +

            "<p>" +

            "The server could not complete the analysis." +

            "</p>";

    }

}

</script>


</body>

</html>
"""


@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...)
):

    try:

        # -----------------------------
        # Validate filename
        # -----------------------------

        if not file.filename:

            raise HTTPException(
                status_code=400,
                detail="No file selected."
            )


        if not file.filename.lower().endswith(
            ".eml"
        ):

            raise HTTPException(
                status_code=400,
                detail="Only .eml email files are supported."
            )


        # -----------------------------
        # Read upload
        # -----------------------------

        content = await file.read()


        # -----------------------------
        # File size protection
        # -----------------------------

        if len(content) > MAX_FILE_SIZE:

            raise HTTPException(
                status_code=413,
                detail="File is too large. Maximum size is 10 MB."
            )


        if not content:

            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty."
            )


        # -----------------------------
        # Parse email
        # -----------------------------

        email = mailparser.parse_from_bytes(
            content
        )


        headers = email.headers


        # -----------------------------
        # Threat analysis
        # -----------------------------

        threat_result = analyze_threat(
            email
        )


        # -----------------------------
        # Email forensics
        # -----------------------------

        forensic_result = analyze_forensics(
            email
        )


        # -----------------------------
        # Sender intelligence
        # -----------------------------

        sender_result = analyze_sender(
            headers.get(
                "From",
                ""
            )
        )


        # -----------------------------
        # AI phishing detection
        # -----------------------------

        email_text = (

            str(
                headers.get(
                    "Subject",
                    ""
                )
            )

            + "\n"

            + str(
                email.text_plain or ""
            )

        )


        try:

            ai_result = analyze_with_ai(
                email_text
            )

        except Exception:

            ai_result = {

                "label": "UNKNOWN",

                "confidence": 0.0,

                "phishing_probability": 0.0

            }


        # -----------------------------
        # Final risk calculation
        # -----------------------------

        final_risk = calculate_risk(

            threat_result,

            forensic_result,

            sender_result,

            ai_result

        )


        # -----------------------------
        # IP intelligence
        # -----------------------------

        ip_intelligence = analyze_ips(

            forensic_result[
                "ip_addresses"
            ]

        )


        # -----------------------------
        # Response
        # -----------------------------

        return {

            "from":
                headers.get(
                    "From",
                    "Unknown"
                ),

            "to":
                headers.get(
                    "To",
                    "Unknown"
                ),

            "subject":
                headers.get(
                    "Subject",
                    "No subject"
                ),

            "date":
                headers.get(
                    "Date",
                    "Unknown"
                ),

            "url_count":
                len(
                    threat_result[
                        "urls"
                    ]
                ),

            "attachment_count":
                len(
                    email.attachments
                ),

            "score":
                final_risk[
                    "score"
                ],

            "risk":
                final_risk[
                    "risk"
                ],

            "indicators":
                (
                    threat_result[
                        "indicators"
                    ]
                    +
                    final_risk[
                        "indicators"
                    ]
                ),

            "urls":
                threat_result[
                    "urls"
                ],

            "message_id":
                forensic_result[
                    "message_id"
                ],

            "received_hops":
                forensic_result[
                    "received_hops"
                ],

            "ip_addresses":
                forensic_result[
                    "ip_addresses"
                ],

            "spf":
                forensic_result[
                    "spf"
                ],

            "dkim":
                forensic_result[
                    "dkim"
                ],

            "dmarc":
                forensic_result[
                    "dmarc"
                ],

            "ip_intelligence":
                ip_intelligence,

            "sender_email":
                sender_result[
                    "email"
                ],

            "sender_username":
                sender_result[
                    "username"
                ],

            "sender_domain":
                sender_result[
                    "domain"
                ],

            "domain_risk":
                sender_result[
                    "domain_risk"
                ],

            "sender_indicators":
                sender_result[
                    "indicators"
                ],

            "ai_label":
                ai_result.get(
                    "label",
                    "UNKNOWN"
                ),

            "ai_confidence":
                ai_result.get(
                    "confidence",
                    0.0
                ),

            "ai_phishing_probability":
                ai_result.get(
                    "phishing_probability",
                    0.0
                )

        }


    except HTTPException:

        raise


    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Email analysis failed. Please verify that the uploaded file is a valid .eml file."
        )