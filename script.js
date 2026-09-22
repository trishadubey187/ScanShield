/* ==================================================
   SCAMSHIELD JAVASCRIPT
================================================== */


/* ==================================================
   GLOBAL VARIABLES
================================================== */

let selectedType = "link";

let lastScanResult = null;


/* ==================================================
   SCANNER SELECTION
================================================== */

function selectScanner(type, button) {

    selectedType = type;


    /* Remove active class */

    const buttons =
        document.querySelectorAll(".scan-option");

    buttons.forEach(btn => {

        btn.classList.remove("active");

    });


    /* Add active class */

    button.classList.add("active");


    /* Change placeholder */

    const input =
        document.getElementById("inputText");


    if (type === "link") {

        input.placeholder =
            "Paste the suspicious link here...";

    }


    else if (type === "email") {

        input.placeholder =
            "Paste the suspicious email here...";

    }


    else if (type === "app") {

        input.placeholder =
            "Enter app name, developer, source or app details...";

    }


    else if (type === "message") {

        input.placeholder =
            "Paste the suspicious SMS, WhatsApp or social media message here...";

    }


    /* Clear previous result */

    document.getElementById("result").style.display =
        "none";

}


/* ==================================================
   CHARACTER COUNTER
================================================== */

document
    .getElementById("inputText")
    .addEventListener("input", function () {

        document.getElementById("charCount").textContent =
            this.value.length;

    });


/* ==================================================
   SCANNER
================================================== */

function scanInput() {


    const input =
        document.getElementById("inputText")
        .value
        .trim();


    const result =
        document.getElementById("result");


    if (input === "") {

        result.style.display = "block";

        result.innerHTML = `

            <div class="result-header">

                <h3>
                    ⚠️ Nothing to scan
                </h3>

            </div>

            <p>
                Please enter a link, email,
                app information or message.
            </p>

        `;

        return;
    }


    let score = 0;

    let reasons = [];


    const text =
        input.toLowerCase();


    /* ==================================================
       LINK SCANNER
    ================================================== */

    if (selectedType === "link") {


        /* HTTP */

        if (
            input.startsWith("http://")
        ) {

            score += 15;

            reasons.push(
                "The link uses HTTP instead of HTTPS."
            );

        }


        /* IP address */

        if (
            /https?:\/\/\d+\.\d+\.\d+\.\d+/
            .test(input)
        ) {

            score += 30;

            reasons.push(
                "The URL uses an IP address instead of a normal domain."
            );

        }


        /* @ symbol */

        if (
            input.includes("@")
        ) {

            score += 20;

            reasons.push(
                "The URL contains an @ symbol, which can be used in deceptive URLs."
            );

        }


        /* Long URL */

        if (
            input.length > 100
        ) {

            score += 10;

            reasons.push(
                "The URL is unusually long."
            );

        }


        /* Suspicious words */

        const linkWords = [

            "login",
            "verify",
            "verification",
            "account",
            "password",
            "urgent",
            "winner",
            "claim",
            "free",
            "security"

        ];


        linkWords.forEach(word => {

            if (
                text.includes(word)
            ) {

                score += 7;

                reasons.push(
                    `Suspicious URL keyword detected: "${word}".`
                );

            }

        });


        /* Short URL */

        const shorteners = [

            "bit.ly",
            "tinyurl",
            "t.co",
            "is.gd",
            "cutt.ly"

        ];


        shorteners.forEach(service => {

            if (
                text.includes(service)
            ) {

                score += 15;

                reasons.push(
                    `URL shortening service detected: ${service}.`
                );

            }

        });

    }


    /* ==================================================
       EMAIL SCANNER
    ================================================== */

    else if (
        selectedType === "email"
    ) {


        const emailWords = [

            "urgent",
            "verify your account",
            "account suspended",
            "password",
            "click here",
            "winner",
            "prize",
            "lottery",
            "otp",
            "bank",
            "refund",
            "claim now",
            "immediately"

        ];


        emailWords.forEach(word => {

            if (
                text.includes(word)
            ) {

                score += 9;

                reasons.push(
                    `Suspicious email phrase detected: "${word}".`
                );

            }

        });


        if (
            text.includes("dear customer")
        ) {

            score += 8;

            reasons.push(
                "The email uses a generic greeting."
            );

        }


        if (
            text.includes("within 24 hours") ||
            text.includes("act now") ||
            text.includes("immediately")
        ) {

            score += 15;

            reasons.push(
                "The message creates strong urgency."
            );

        }


        if (
            text.includes("otp")
        ) {

            score += 20;

            reasons.push(
                "The email asks for or mentions an OTP."
            );

        }

    }


    /* ==================================================
       APP SCANNER
    ================================================== */

    else if (
        selectedType === "app"
    ) {


        const appWords = [

            "mod apk",
            "cracked",
            "premium free",
            "free money",
            "unlimited money",
            "hack",
            "unknown developer",
            "unknown source",
            "modified app",
            "pirated"

        ];


        appWords.forEach(word => {

            if (
                text.includes(word)
            ) {

                score += 15;

                reasons.push(
                    `Suspicious app indicator detected: "${word}".`
                );

            }

        });


        if (
            text.includes("unknown source")
        ) {

            score += 20;

            reasons.push(
                "The application appears to come from an unknown source."
            );

        }

    }


    /* ==================================================
       MESSAGE SCANNER
    ================================================== */

    else if (
        selectedType === "message"
    ) {


        const messageWords = [

            "congratulations",
            "you won",
            "winner",
            "prize",
            "lottery",
            "click here",
            "claim now",
            "urgent",
            "otp",
            "password",
            "bank",
            "send money",
            "refund",
            "account blocked",
            "account suspended",
            "kyc",
            "verify now"

        ];


        messageWords.forEach(word => {

            if (
                text.includes(word)
            ) {

                score += 9;

                reasons.push(
                    `Suspicious message phrase detected: "${word}".`
                );

            }

        });


        if (
            text.includes("send money")
        ) {

            score += 20;

            reasons.push(
                "The message requests a money transfer."
            );

        }

    }


    /* ==================================================
       LIMIT SCORE
    ================================================== */

    score =
        Math.min(score, 100);


    /* ==================================================
       RISK LEVEL
    ================================================== */

    let riskLevel;

    let riskClass;


    if (
        score >= 60
    ) {

        riskLevel = "HIGH RISK";

        riskClass = "risk-high";

    }

    else if (
        score >= 30
    ) {

        riskLevel = "MEDIUM RISK";

        riskClass = "risk-medium";

    }

    else {

        riskLevel = "LOW RISK";

        riskClass = "risk-low";

    }


    /* ==================================================
       NO REASONS
    ================================================== */

    if (
        reasons.length === 0
    ) {

        reasons.push(
            "No obvious suspicious indicators were detected by this basic scanner."
        );

    }


    /* ==================================================
       SAVE RESULT
    ================================================== */

    lastScanResult = {

        type: selectedType,

        score: score,

        risk: riskLevel,

        reasons: reasons

    };


    /* ==================================================
       DISPLAY RESULT
    ================================================== */

    result.style.display =
        "block";


    result.innerHTML = `

        <div class="result-header">

            <div>

                <h2>
                    🔍 Scan Complete
                </h2>

                <p>
                    ${selectedType.toUpperCase()} analysis
                </p>

            </div>

            <div
                class="risk-badge ${riskClass}">

                ${riskLevel}

            </div>

        </div>


        <h3>
            Risk Score: ${score}/100
        </h3>


        <div class="score-bar">

            <div
                class="score-fill"
                style="width:${score}%">
            </div>

        </div>


        <h3>
            🚨 Detected Indicators
        </h3>


        <ul>

            ${reasons
                .map(reason =>
                    `<li>${reason}</li>`
                )
                .join("")
            }

        </ul>


        <br>


        <p>

            🛡️ <strong>Safety recommendation:</strong>

            ${
                score >= 60
                ?
                "Avoid interacting with this content. Do not provide passwords, OTPs or payment information. Verify through an official source."
                :
                score >= 30
                ?
                "Be cautious. Independently verify the sender, website or app before taking action."
                :
                "No obvious warning signs were detected, but always verify unexpected requests before trusting them."
            }

        </p>


        <br>


        <button
            class="ai-btn"
            onclick="askAIAboutScan()">

            🤖 Ask AI About This Result

        </button>

    `;


    /* Scroll result into view */

    result.scrollIntoView({

        behavior: "smooth",

        block: "center"

    });

}


/* ==================================================
   AI CHAT
================================================== */

function addChatMessage(
    message,
    type
) {


    const chatBox =
        document.getElementById("chatBox");


    const messageDiv =
        document.createElement("div");


    messageDiv.className =
        `chat-message ${type}`;


    const avatar =
        type === "bot"
        ? "🤖"
        : "👤";


    const name =
        type === "bot"
        ? "ScamShield AI"
        : "You";


    messageDiv.innerHTML = `

        <div class="avatar">
            ${avatar}
        </div>

        <div class="message-content">

            <strong>
                ${name}
            </strong>

            <p>
                ${message}
            </p>

        </div>

    `;


    chatBox.appendChild(
        messageDiv
    );


    chatBox.scrollTop =
        chatBox.scrollHeight;

}


/* ==================================================
   USER MESSAGE
================================================== */

function sendMessage() {


    const input =
        document.getElementById("chatInput");


    const question =
        input.value.trim();


    if (
        question === ""
    ) {

        return;

    }


    addChatMessage(
        escapeHTML(question),
        "user"
    );


    input.value = "";


    setTimeout(() => {

        const answer =
            generateAIResponse(question);


        addChatMessage(
            answer,
            "bot"
        );

    }, 500);

}


/* ==================================================
   QUICK QUESTION
================================================== */

function quickQuestion(question) {


    document.getElementById(
        "chatInput"
    ).value = question;


    sendMessage();

}


/* ==================================================
   ENTER KEY
================================================== */

function handleChatKey(event) {

    if (
        event.key === "Enter"
    ) {

        sendMessage();

    }

}


/* ==================================================
   AI RESPONSE ENGINE
================================================== */

function generateAIResponse(question) {


    const q =
        question.toLowerCase();


    /* PHISHING */

    if (
        q.includes("phishing")
    ) {

        return `

            🎣 <strong>Phishing</strong> is a type of
            online scam where someone tries to trick you
            into giving sensitive information or visiting
            a malicious website.

            <br><br>

            Common warning signs include suspicious links,
            unexpected login requests, urgency and requests
            for passwords or verification codes.

        `;

    }


    /* FAKE WEBSITE */

    if (
        q.includes("fake website") ||
        q.includes("fake site") ||
        q.includes("website safe")
    ) {

        return `

            🌐 Check the website address carefully.

            <br><br>

            Look for misspelled domains, unexpected
            subdomains, unusual URLs and suspicious
            requests for passwords or payments.

            <br><br>

            If you are unsure, open the service through
            its official app or manually type its known
            website address instead of following the
            suspicious link.

        `;

    }


    /* OTP */

    if (
        q.includes("otp") ||
        q.includes("verification code")
    ) {

        return `

            🔐 Never share an OTP or verification code
            with someone who unexpectedly contacts you.

            <br><br>

            If someone asks you to read out a code,
            stop and verify who they are using an
            independent, trusted contact method.

        `;

    }


    /* PASSWORD */

    if (
        q.includes("password")
    ) {

        return `

            🔑 Use a unique, strong password for each
            important account.

            <br><br>

            Avoid entering your password through an
            unfamiliar link. Use the official website
            or app instead.

            <br><br>

            Where available, enable multi-factor
            authentication.

        `;

    }


    /* EMAIL */

    if (
        q.includes("email") ||
        q.includes("mail")
    ) {

        return `

            📧 For a suspicious email, check:

            <br><br>

            • The actual sender address<br>
            • Unexpected attachments<br>
            • Urgent requests<br>
            • Suspicious links<br>
            • Requests for passwords or money

            <br><br>

            Don't rely only on logos or the displayed
            sender name.

        `;

    }


    /* LINK */

    if (
        q.includes("link") ||
        q.includes("url")
    ) {

        return `

            🔗 Before opening an unfamiliar link,
            carefully inspect the domain.

            <br><br>

            Be cautious with misspellings, unexpected
            domains, URL shorteners and links received
            unexpectedly.

            <br><br>

            When possible, navigate to the service
            through its official website or app.

        `;

    }


    /* MALWARE */

    if (
        q.includes("malware") ||
        q.includes("virus")
    ) {

        return `

            🦠 Malware is software designed to perform
            unwanted or harmful actions.

            <br><br>

            Reduce risk by keeping software updated,
            installing applications from trusted sources,
            and avoiding suspicious downloads and
            attachments.

        `;

    }


    /* HACKED ACCOUNT */

    if (
        q.includes("hacked") ||
        q.includes("account hacked") ||
        q.includes("account stolen")
    ) {

        return `

            🛡️ If you think an account has been
            compromised:

            <br><br>

            1. Use the service's official recovery process.<br>
            2. Change the password from a trusted device.<br>
            3. Enable multi-factor authentication if available.<br>
            4. Review recent sessions and security activity.<br>
            5. Contact the service's official support channel.

        `;

    }


    /* PAYMENT */

    if (
        q.includes("money") ||
        q.includes("payment") ||
        q.includes("upi") ||
        q.includes("bank")
    ) {

        return `

            💳 Never transfer money just because an
            unexpected message or caller asks you to.

            <br><br>

            Verify the request independently using
            a trusted contact method or the official
            service/app.

        `;

    }


    /* APP */

    if (
        q.includes("app") ||
        q.includes("apk")
    ) {

        return `

            📱 Prefer applications from official app
            stores and verify the developer.

            <br><br>

            Be especially cautious with modified,
            cracked or unknown-source applications.

        `;

    }


    /* SCAM */

    if (
        q.includes("scam") ||
        q.includes("fraud")
    ) {

        return `

            🚨 Common scam warning signs include:

            <br><br>

            • Unexpected contact<br>
            • Strong urgency<br>
            • Requests for money<br>
            • Requests for OTP/passwords<br>
            • Suspicious links<br>
            • Unrealistic prizes or offers

            <br><br>

            When something feels unusual, stop and
            independently verify it.

        `;

    }


    /* DEFAULT */

    return `

        🤖 I can help with cybersecurity topics such as:

        <br><br>

        🎣 Phishing<br>
        🔗 Suspicious links<br>
        📧 Fake emails<br>
        📱 Suspicious apps<br>
        💬 Scam messages<br>
        🔐 OTP and password safety<br>
        🦠 Malware<br>
        🛡️ Account security<br>
        💳 Payment scams

        <br><br>

        Try asking a specific question, for example:
        <strong>"How can I identify a fake website?"</strong>

    `;

}


/* ==================================================
   ASK AI ABOUT SCAN
================================================== */

function askAIAboutScan() {


    if (
        !lastScanResult
    ) {

        return;

    }


    let message =

        `I scanned a ${lastScanResult.type} and got a ${lastScanResult.risk} result with a score of ${lastScanResult.score}/100. Explain what I should do.`;


    addChatMessage(
        escapeHTML(message),
        "user"
    );


    setTimeout(() => {


        let response;


        if (
            lastScanResult.score >= 60
        ) {

            response = `

                🚨 This scan produced a
                <strong>HIGH RISK</strong> result.

                <br><br>

                The scanner found several indicators
                associated with suspicious content.

                <br><br>

                🛡️ Recommended action:

                <br>

                • Don't click suspicious links.<br>
                • Don't provide passwords or OTPs.<br>
                • Don't send money.<br>
                • Verify through an official source.

                <br><br>

                Remember that this scanner uses
                indicators and cannot guarantee whether
                content is malicious.

            `;

        }


        else if (
            lastScanResult.score >= 30
        ) {

            response = `

                ⚠️ This scan produced a
                <strong>MEDIUM RISK</strong> result.

                <br><br>

                Some suspicious indicators were detected.

                <br><br>

                I recommend independently verifying
                the sender, website, app or request
                before taking action.

            `;

        }


        else {

            response = `

                🟢 This scan produced a
                <strong>LOW RISK</strong> result.

                <br><br>

                The basic scanner did not detect
                many common warning indicators.

                <br><br>

                However, a low score does not prove
                that something is completely safe.
                Always consider the context.

            `;

        }


        addChatMessage(
            response,
            "bot"
        );


    }, 500);

}


/* ==================================================
   HTML ESCAPE
================================================== */

function escapeHTML(text) {

    const div =
        document.createElement("div");

    div.textContent =
        text;

    return div.innerHTML;

}