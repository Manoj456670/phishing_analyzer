// Trusted domains list for typosquatting checks
const TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "facebook.com", "instagram.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "github.com", "dropbox.com", "linkedin.com", "adobe.com"
];

// PS 3 Urgency keywords
const URGENCY_KEYWORDS = [
    "act now", "verify immediately", "immediate action", "account suspended",
    "unauthorized access", "urgent", "locked out", "suspicious activity",
    "security alert", "expires within", "failure to respond", "update payment",
    "confirm identity", "password reset requested", "final warning", "limited time"
];

const DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".jar", ".hta", ".iso"];

// Levenshtein similarity algorithm for typosquatting/lookalikes
function similarityRatio(s1, s2) {
    let longer = s1.length >= s2.length ? s1 : s2;
    let shorter = s1.length < s2.length ? s1 : s2;
    let longerLength = longer.length;
    if (longerLength === 0) return 1.0;
    
    let costs = [];
    for (let i = 0; i <= longer.length; i++) {
        let lastValue = i;
        for (let j = 0; j <= shorter.length; j++) {
            if (i === 0) costs[j] = j;
            else {
                if (j > 0) {
                    let newValue = costs[j - 1];
                    if (longer.charAt(i - 1) !== shorter.charAt(j - 1))
                        newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                    costs[j - 1] = lastValue;
                    lastValue = newValue;
                }
            }
        }
        if (i > 0) costs[shorter.length] = lastValue;
    }
    return (longerLength - costs[shorter.length]) / parseFloat(longerLength);
}

function extractDomain(emailStr) {
    if (!emailStr) return "";
    const match = emailStr.match(/@([\w.-]+)/);
    return match ? match[1].toLowerCase().replace(">", "").trim() : "";
}

function detectLookalike(domain) {
    const clean = domain.toLowerCase();
    for (let trusted of TRUSTED_DOMAINS) {
        if (clean === trusted) return null; // Exact match is authentic
        const sim = similarityRatio(clean, trusted);
        if (sim >= 0.75 && sim < 1.0) {
            return trusted;
        }
    }
    return null;
}

// RFC 822 / .EML Parser in pure JS
function parseAndAnalyze(rawContent) {
    let flags = [];
    let score = 0;

    // Split headers and body
    const parts = rawContent.split(/\r?\n\r?\n/);
    const headerBlock = parts[0] || "";
    const bodyBlock = parts.slice(1).join("\n") || "";

    const getHeader = (name) => {
        const regex = new RegExp(`^${name}:[ \\t]*(.*)$`, "gmi");
        const match = regex.exec(headerBlock);
        return match ? match[1].trim() : "";
    };

    const fromHeader = getHeader("From");
    const replyToHeader = getHeader("Reply-To");
    const subject = getHeader("Subject") || "(No Subject)";
    const dateHeader = getHeader("Date") || "Unknown";

    const fromDomain = extractDomain(fromHeader);
    const replyToDomain = extractDomain(replyToHeader);

    // Rule 1: From vs Reply-To mismatch (+3 pts)
    if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
        score += 3;
        flags.push({
            rule: "From vs Reply-To Mismatch",
            points: 3,
            evidence: `From: <${fromDomain}> does not match Reply-To: <${replyToDomain}>`,
            explanation: "Attackers often spoof the sender display address while directing replies to a mailbox they control."
        });
    }

    // Rule 2: Lookalike domain detected (+4 pts)
    if (fromDomain) {
        const spoofed = detectLookalike(fromDomain);
        if (spoofed) {
            score += 4;
            flags.push({
                rule: "Lookalike Domain Detected",
                points: 4,
                evidence: `Sender domain '${fromDomain}' closely resembles trusted brand '${spoofed}'`,
                explanation: "Phishers use slight misspellings or homoglyphs to trick users into trusting fake domains."
            });
        }
    }

    // Rule 3: Link Text vs URL mismatch (+3 pts)
    const parser = new DOMParser();
    const doc = parser.parseFromString(bodyBlock, "text/html");
    const links = doc.querySelectorAll("a[href]");
    let linkMismatches = [];

    links.forEach(a => {
        const text = a.textContent.trim();
        const href = a.getAttribute("href").trim();
        if (/^https?:\/\//i.test(text)) {
            try {
                const textHost = new URL(text).hostname.toLowerCase();
                const hrefHost = new URL(href).hostname.toLowerCase();
                if (textHost && hrefHost && textHost !== hrefHost) {
                    linkMismatches.push(`Label: '${text}' points to '${href}'`);
                }
            } catch (e) {}
        }
    });

    if (linkMismatches.length > 0) {
        score += 3;
        flags.push({
            rule: "Link Text vs Actual URL Mismatch",
            points: 3,
            evidence: linkMismatches.slice(0, 2).join("; "),
            explanation: "The visible anchor text displays a legitimate address, but the real hyperlink sends users to an attacker-controlled server."
        });
    }

    // Rule 4: Urgency language detected (+2 pts)
    const combinedText = (subject + " " + doc.body.textContent).toLowerCase();
    let detectedUrgency = [];
    URGENCY_KEYWORDS.forEach(phrase => {
        const regex = new RegExp(`\\b${phrase}\\b`, "i");
        if (regex.test(combinedText)) {
            detectedUrgency.push(phrase);
        }
    });

    if (detectedUrgency.length > 0) {
        score += 2;
        flags.push({
            rule: "Urgency / Threatening Language",
            points: 2,
            evidence: `Matched urgency triggers: ${[...new Set(detectedUrgency)].join(", ")}`,
            explanation: "Phishing emails create an artificial sense of urgency to bypass rational scrutiny and force hasty actions."
        });
    }

    // Rule 5: Risky Attachment Check (+3 pts)
    const attachmentMatches = [...headerBlock.matchAll(/filename="?([^"\r\n]+)"?/gi), ...bodyBlock.matchAll(/filename="?([^"\r\n]+)"?/gi)];
    const filenames = attachmentMatches.map(m => m[1]);
    const riskyFiles = filenames.filter(f => DANGEROUS_EXTENSIONS.some(ext => f.toLowerCase().endsWith(ext)));

    if (riskyFiles.length > 0) {
        score += 3;
        flags.push({
            rule: "Suspicious Executable Attachment",
            points: 3,
            evidence: `Dangerous file detected: ${riskyFiles.join(", ")}`,
            explanation: "Executables, scripts, or installer files are frequently used to deliver malware payloads."
        });
    }

    // Verdict Scale (Slide 6)
    let verdict = "SAFE";
    let color = "success";
    if (score >= 6) {
        verdict = "PHISHING";
        color = "danger";
    } else if (score >= 3) {
        verdict = "SUSPICIOUS";
        color = "warning";
    }

    return {
        metadata: {
            from: fromHeader || "Unknown",
            reply_to: replyToHeader || "None specified",
            subject: subject,
            date: dateHeader,
            attachments_count: filenames.length
        },
        score: score,
        verdict: verdict,
        verdict_color: color,
        flags: flags
    };
}

// UI Event Handlers
document.addEventListener("DOMContentLoaded", () => {
    const tabUploadBtn = document.getElementById("tabUploadBtn");
    const tabPasteBtn = document.getElementById("tabPasteBtn");
    const uploadPane = document.getElementById("uploadPane");
    const pastePane = document.getElementById("pastePane");
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const fileNameDisplay = document.getElementById("fileNameDisplay");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const rawEmailInput = document.getElementById("rawEmailInput");
    const resultsSection = document.getElementById("resultsSection");

    let currentMode = "upload";
    let selectedFileText = "";

    tabUploadBtn.addEventListener("click", () => {
        currentMode = "upload";
        tabUploadBtn.classList.add("active");
        tabPasteBtn.classList.remove("active");
        uploadPane.classList.add("active");
        pastePane.classList.remove("active");
    });

    tabPasteBtn.addEventListener("click", () => {
        currentMode = "paste";
        tabPasteBtn.classList.add("active");
        tabUploadBtn.classList.remove("active");
        pastePane.classList.add("active");
        uploadPane.classList.remove("active");
    });

    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.style.borderColor = "var(--accent)"; });
    dropZone.addEventListener("dragleave", () => { dropZone.style.borderColor = "var(--border)"; });
    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.style.borderColor = "var(--border)";
        if (e.dataTransfer.files.length > 0) processFile(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) processFile(e.target.files[0]);
    });

    function processFile(file) {
        if (!file.name.endsWith(".eml")) {
            alert("Please choose a valid .eml file.");
            return;
        }
        fileNameDisplay.textContent = `Selected: ${file.name}`;
        const reader = new FileReader();
        reader.onload = (e) => { selectedFileText = e.target.result; };
        reader.readAsText(file);
    }

    analyzeBtn.addEventListener("click", () => {
        const textToAnalyze = (currentMode === "upload") ? selectedFileText : rawEmailInput.value;
        if (!textToAnalyze || textToAnalyze.trim().length === 0) {
            alert("Please select a .eml file or paste email headers/content first!");
            return;
        }

        const data = parseAndAnalyze(textToAnalyze);

        // Update UI
        resultsSection.classList.remove("hidden");
        document.getElementById("verdictText").textContent = data.verdict;
        document.getElementById("scoreValue").textContent = data.score;

        const banner = document.getElementById("verdictBanner");
        banner.className = `card verdict-card ${data.verdict_color}`;

        const summary = document.getElementById("verdictSummary");
        if (data.verdict === "SAFE") {
            document.getElementById("verdictText").style.color = "#3fb950";
            summary.textContent = "No significant phishing flags were triggered. The email appears genuine.";
        } else if (data.verdict === "SUSPICIOUS") {
            document.getElementById("verdictText").style.color = "#e3b341";
            summary.textContent = "Several warning signs detected. Review the flags carefully before interacting.";
        } else {
            document.getElementById("verdictText").style.color = "#f85149";
            summary.textContent = "High-risk indicators identified. This email is very likely a phishing attack.";
        }

        document.getElementById("metaFrom").textContent = data.metadata.from;
        document.getElementById("metaReplyTo").textContent = data.metadata.reply_to;
        document.getElementById("metaSubject").textContent = data.metadata.subject;
        document.getElementById("metaDate").textContent = data.metadata.date;
        document.getElementById("metaAttachments").textContent = `${data.metadata.attachments_count} found`;

        const flagsContainer = document.getElementById("flagsContainer");
        flagsContainer.innerHTML = "";

        if (data.flags.length === 0) {
            flagsContainer.innerHTML = "<p style='color: var(--text-secondary);'>Clean email. No malicious rules triggered.</p>";
        } else {
            data.flags.forEach(f => {
                const box = document.createElement("div");
                box.className = "flag-box";
                box.innerHTML = `
                    <div class="flag-title">
                        <span>${f.rule}</span>
                        <span class="flag-points">+${f.points} pts</span>
                    </div>
                    <div class="flag-evidence">${f.evidence}</div>
                    <div class="flag-explanation">${f.explanation}</div>
                `;
                flagsContainer.appendChild(box);
            });
        }

        resultsSection.scrollIntoView({ behavior: "smooth" });
    });
});
