/* =========================================
   CYBERGUARDIAN — FRONTEND CONTROLLER
   ========================================= */

"use strict";


/* CONFIGURATION */

const API_BASE = window.location.origin;

const SCAN_ENDPOINT = `${API_BASE}/scan`;
const HEALTH_ENDPOINT = `${API_BASE}/`;

const REQUEST_TIMEOUT = 30000;


/* SESSION DATA */

const scanHistory = [];

const sessionStats = {
    total: 0,
    safe: 0,
    threats: 0,
    durations: []
};

let lastScanTime = null;
let isScanning = false;


/* DOM HELPERS */

function $(id) {
    return document.getElementById(id);
}

function setText(id, value) {
    const element = $(id);

    if (element) {
        element.textContent = value;
    }
}

function setWidth(id, value) {
    const element = $(id);

    if (element) {
        element.style.width = `${value}%`;
    }
}

function clampPercentage(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return 0;
    }

    return Math.min(100, Math.max(0, number));
}

function formatNumber(value) {
    return String(value).padStart(3, "0");
}

function getCurrentTime() {
    return new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
    });
}

function getTimestamp() {
    return new Date().toLocaleString();
}


/* CLOCK */

function updateClock() {
    const clock = $("systemClock");

    if (!clock) {
        return;
    }

    clock.textContent = getCurrentTime();
}

updateClock();

setInterval(updateClock, 1000);


/* MOBILE NAVIGATION */

function setupMobileNavigation() {
    const menuButton = $("mobileMenuButton");
    const navigation = $("mainNavigation");

    if (!menuButton || !navigation) {
        return;
    }

    menuButton.addEventListener("click", () => {
        const isOpen = navigation.classList.toggle("open");

        menuButton.setAttribute("aria-expanded", String(isOpen));

        menuButton.setAttribute(
            "aria-label",
            isOpen ? "Close navigation" : "Open navigation"
        );
    });

    navigation.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", () => {
            navigation.classList.remove("open");

            menuButton.setAttribute("aria-expanded", "false");
            menuButton.setAttribute("aria-label", "Open navigation");
        });
    });
}


/* BACKEND STATUS */

async function checkBackend() {
    const statusText = $("scannerStatusText");
    const statusLight = $("scannerStatusLight");

    try {
        const response = await fetch(HEALTH_ENDPOINT, {
            method: "GET",
            cache: "no-store",
            signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) {
            throw new Error("Backend returned an unsuccessful response.");
        }

        const data = await response.json();

        const isAvailable =
            data &&
            (
                data.status === "success" ||
                data.status === "ok"
            );

        if (!isAvailable) {
            throw new Error("Unexpected backend health response.");
        }

        updateBackendUI(true);

        if (statusText) {
            statusText.textContent = "ANALYSIS ENGINE ONLINE";
        }

        if (statusLight) {
            statusLight.classList.add("online");
            statusLight.classList.remove("offline");
        }

    } catch (error) {
        updateBackendUI(false);

        if (statusText) {
            statusText.textContent = "BACKEND UNAVAILABLE";
        }

        if (statusLight) {
            statusLight.classList.add("offline");
            statusLight.classList.remove("online");
        }
    }
}


function updateBackendUI(isOnline) {
    const backendText = isOnline ? "RUNNING" : "OFFLINE";

    setText("heroBackendStatus", backendText);
    setText("statusApi", isOnline ? "ONLINE" : "OFFLINE");
    setText("statusEngine", isOnline ? "AVAILABLE" : "UNAVAILABLE");
    setText("footerBackendStatus", isOnline ? "ENGINE ONLINE" : "ENGINE OFFLINE");

    setText(
        "operationalMessage",
        isOnline
            ? "BACKEND CONNECTION ESTABLISHED"
            : "BACKEND CONNECTION FAILED"
    );

    const message = $("operationalMessage");

    if (message) {
        message.innerHTML = "";

        const dot = document.createElement("span");
        dot.className = "lime-dot";

        if (!isOnline) {
            dot.style.background = "var(--danger)";
        }

        message.appendChild(dot);

        message.appendChild(
            document.createTextNode(
                isOnline
                    ? "BACKEND CONNECTION ESTABLISHED"
                    : "BACKEND CONNECTION FAILED"
            )
        );
    }
}


/* URL VALIDATION */

function validateURL(rawValue) {
    const value = rawValue.trim();

    if (!value) {
        return {
            valid: false,
            message: "ENTER A URL BEFORE STARTING THE SCAN."
        };
    }

    let parsed;

    try {
        parsed = new URL(value);
    } catch {
        return {
            valid: false,
            message: "INVALID URL FORMAT. INCLUDE HTTPS:// OR HTTP://."
        };
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        return {
            valid: false,
            message: "ONLY HTTP AND HTTPS URLS ARE SUPPORTED."
        };
    }

    if (!parsed.hostname || !parsed.hostname.includes(".")) {
        return {
            valid: false,
            message: "ENTER A VALID HOSTNAME."
        };
    }

    if (/\s/.test(value)) {
        return {
            valid: false,
            message: "THE URL CANNOT CONTAIN SPACES."
        };
    }

    return {
        valid: true,
        value: parsed.href
    };
}


/* API REQUEST */

async function requestScan(url) {
    const controller = new AbortController();

    const timeoutId = setTimeout(() => {
        controller.abort();
    }, REQUEST_TIMEOUT);

    try {
        const response = await fetch(SCAN_ENDPOINT, {
            method: "POST",

            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },

            body: JSON.stringify({
                url: url
            }),

            signal: controller.signal
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
            const detail =
                data?.detail ||
                data?.message ||
                `HTTP ${response.status}`;

            throw new Error(String(detail));
        }

        if (!data || typeof data !== "object") {
            throw new Error("The backend returned an invalid response.");
        }

        if (data.status === "error") {
            throw new Error(data.message || "The scan could not be completed.");
        }

        return data;

    } finally {
        clearTimeout(timeoutId);
    }
}


/* VERDICT NORMALIZATION */

function normalizeVerdict(rawVerdict) {
    const value = String(rawVerdict || "")
        .trim()
        .toLowerCase();

    if (
        value.includes("malicious") ||
        value.includes("phishing")
    ) {
        return "MALICIOUS";
    }

    if (
        value.includes("suspicious") ||
        value.includes("warning")
    ) {
        return "SUSPICIOUS";
    }

    if (
        value.includes("safe") ||
        value.includes("benign") ||
        value.includes("legitimate")
    ) {
        return "SAFE";
    }

    return "UNKNOWN";
}


function verdictClass(verdict) {
    if (verdict === "SAFE") {
        return "safe";
    }

    if (verdict === "SUSPICIOUS") {
        return "suspicious";
    }

    if (verdict === "MALICIOUS") {
        return "malicious";
    }

    return "error";
}


function verdictSymbol(verdict) {
    if (verdict === "SAFE") {
        return "✓";
    }

    if (verdict === "SUSPICIOUS") {
        return "!";
    }

    if (verdict === "MALICIOUS") {
        return "×";
    }

    return "?";
}


/* RESULT EXTRACTION */

function extractResult(data, requestedURL) {
    const prediction = normalizeVerdict(data.prediction);

    const confidence = clampPercentage(data.confidence);
    const riskScore = clampPercentage(data.risk_score);

    const safeProbability = clampPercentage(
        data.safe_probability
    );

    const phishingProbability = clampPercentage(
        data.phishing_probability
    );

    const reasons = Array.isArray(data.reasons)
        ? data.reasons.map((reason) => String(reason))
        : [];

    return {
        url: requestedURL,

        prediction: prediction,

        confidence: confidence,
        riskScore: riskScore,

        safeProbability: safeProbability,
        phishingProbability: phishingProbability,

        reasons: reasons,

        duplicate: Boolean(data.duplicate),

        raw: data
    };
}


/* DISPLAY RESULT */

function displayResult(result, duration) {
    const emptyResult = $("emptyResult");
    const scanResult = $("scanResult");

    if (emptyResult) {
        emptyResult.classList.add("hidden");
    }

    if (scanResult) {
        scanResult.classList.remove("hidden");
    }

    const banner = $("verdictBanner");
    const verdict = result.prediction;
    const styleClass = verdictClass(verdict);

    if (banner) {
        banner.classList.remove(
            "safe",
            "suspicious",
            "malicious",
            "error"
        );

        banner.classList.add(styleClass);
    }

    setText("verdictIcon", verdictSymbol(verdict));

    setText(
        "verdictText",
        verdict === "UNKNOWN" ? "UNKNOWN VERDICT" : verdict
    );

    setText(
        "verdictTag",
        result.duplicate ? "REPEATED URL" : "MODEL OUTPUT"
    );

    setText("confidenceValue", `${result.confidence.toFixed(2)}%`);
    setText("riskValue", `${Math.round(result.riskScore)}/100`);

    setText("safeProbabilityValue", `${result.safeProbability.toFixed(2)}%`);

    setText(
        "phishingProbabilityValue",
        `${result.phishingProbability.toFixed(2)}%`
    );

    setText("scannedTarget", result.url);
    setText("resultTimestamp", getCurrentTime());

    setText(
        "resultFooterStatus",
        `COMPLETE / ${duration.toFixed(0)} MS`
    );

    setWidth("safeBar", result.safeProbability);
    setWidth("phishingBar", result.phishingProbability);

    const safeProgress = $("safeProgress");
    const phishingProgress = $("phishingProgress");

    if (safeProgress) {
        safeProgress.setAttribute(
            "aria-valuenow",
            String(result.safeProbability)
        );
    }

    if (phishingProgress) {
        phishingProgress.setAttribute(
            "aria-valuenow",
            String(result.phishingProbability)
        );
    }

    displayReasons(result.reasons);

    if (verdict === "SAFE") {
        setScanMessage(
            "ANALYSIS COMPLETE. MODEL CLASSIFIED THIS URL AS SAFE.",
            "success"
        );

    } else if (verdict === "SUSPICIOUS") {
        setScanMessage(
            "WARNING. THE MODEL FLAGGED THIS URL AS SUSPICIOUS.",
            "warning"
        );

    } else if (verdict === "MALICIOUS") {
        setScanMessage(
            "THREAT WARNING. THE MODEL FLAGGED THIS URL AS MALICIOUS.",
            "danger"
        );

    } else {
        setScanMessage(
            "ANALYSIS COMPLETE, BUT THE MODEL VERDICT IS UNRECOGNIZED.",
            "warning"
        );
    }
}


/* REASONS */

function displayReasons(reasons) {
    const list = $("reasonsList");

    if (!list) {
        return;
    }

    list.replaceChildren();

    if (!reasons.length) {
        const item = document.createElement("li");

        item.textContent =
            "The model did not provide any explanation for this result.";

        list.appendChild(item);
        return;
    }

    reasons.forEach((reason) => {
        const item = document.createElement("li");

        // textContent prevents model-provided text from being treated as HTML.
        item.textContent = reason;

        list.appendChild(item);
    });
}


/* STATUS MESSAGE */

function setScanMessage(message, type = "normal") {
    const element = $("scanMessage");

    if (!element) {
        return;
    }

    element.textContent = message;

    element.style.color =
        type === "success"
            ? "var(--lime)"
            : type === "danger"
                ? "var(--danger)"
                : type === "warning"
                    ? "var(--warning)"
                    : "var(--text-muted)";
}


/* SCAN BUTTON */

function setScanningState(scanning) {
    isScanning = scanning;

    const button = $("scanButton");
    const buttonText = $("scanButtonText");

    if (button) {
        button.disabled = scanning;
    }

    if (buttonText) {
        buttonText.textContent = scanning
            ? "ANALYZING TARGET..."
            : "EXECUTE ANALYSIS";
    }
}


/* MAIN SCAN HANDLER */

async function handleScan(event) {
    event.preventDefault();

    if (isScanning) {
        return;
    }

    const input = $("urlInput");

    if (!input) {
        return;
    }

    const validation = validateURL(input.value);

    if (!validation.valid) {
        setScanMessage(validation.message, "warning");
        input.focus();
        return;
    }

    const url = validation.value;

    input.value = url;

    setScanningState(true);

    setScanMessage(
        "REQUEST SENT. WAITING FOR MODEL CLASSIFICATION..."
    );

    const startTime = performance.now();

    try {
        const data = await requestScan(url);

        const duration = performance.now() - startTime;

        const result = extractResult(data, url);

        displayResult(result, duration);

        recordScan(result, duration);

        setText("statusLastScan", getCurrentTime());

    } catch (error) {
        const message =
            error.name === "AbortError" || error.name === "TimeoutError"
                ? "SCAN TIMED OUT. CHECK WHETHER THE BACKEND IS RUNNING."
                : error.message || "UNKNOWN CONNECTION ERROR.";

        setScanMessage(`SCAN FAILED: ${message}`, "danger");

        displayScanError(message);

    } finally {
        setScanningState(false);

        checkBackend();
    }
}


/* DISPLAY ERROR */

function displayScanError(message) {
    const emptyResult = $("emptyResult");
    const scanResult = $("scanResult");

    if (emptyResult) {
        emptyResult.classList.add("hidden");
    }

    if (scanResult) {
        scanResult.classList.remove("hidden");
    }

    const banner = $("verdictBanner");

    if (banner) {
        banner.classList.remove("safe", "suspicious", "malicious");
        banner.classList.add("error");
    }

    setText("verdictIcon", "!");
    setText("verdictText", "SCAN FAILED");
    setText("verdictTag", "CONNECTION ERROR");

    setText("confidenceValue", "—");
    setText("riskValue", "—");
    setText("safeProbabilityValue", "—");
    setText("phishingProbabilityValue", "—");

    setText("scannedTarget", $("urlInput")?.value || "Unknown URL");

    setWidth("safeBar", 0);
    setWidth("phishingBar", 0);

    displayReasons([
        message,
        "Verify that the FastAPI backend is running and reachable."
    ]);

    setText("resultTimestamp", getCurrentTime());
    setText("resultFooterStatus", "ERROR");
}


/* SESSION HISTORY */

function recordScan(result, duration) {
    sessionStats.total += 1;

    if (result.prediction === "SAFE") {
        sessionStats.safe += 1;
    } else if (
        result.prediction === "SUSPICIOUS" ||
        result.prediction === "MALICIOUS"
    ) {
        sessionStats.threats += 1;
    }

    sessionStats.durations.push(duration);

    lastScanTime = new Date();

    const record = {
        time: getCurrentTime(),
        timestamp: getTimestamp(),

        url: result.url,
        verdict: result.prediction,

        risk: result.riskScore,
        duration: duration
    };

    scanHistory.unshift(record);

    // Keep the latest 50 records in browser memory.
    if (scanHistory.length > 50) {
        scanHistory.pop();
    }

    updateStatistics();
    renderHistory();
}


function updateStatistics() {
    setText("totalScans", formatNumber(sessionStats.total));

    setText("safeScans", formatNumber(sessionStats.safe));

    setText("threatScans", formatNumber(sessionStats.threats));

    setText("stripTotalScans", formatNumber(sessionStats.total));

    setText("stripThreats", formatNumber(sessionStats.threats));

    const average =
        sessionStats.durations.length > 0
            ? sessionStats.durations.reduce((sum, item) => sum + item, 0) /
              sessionStats.durations.length
            : null;

    setText(
        "avgTime",
        average === null ? "—" : `${average.toFixed(0)} ms`
    );

    setText("statusScans", formatNumber(sessionStats.total));
}


/* HISTORY TABLE */

function renderHistory() {
    const tbody = $("historyBody");

    if (!tbody) {
        return;
    }

    tbody.replaceChildren();

    setText("historyCount", `${scanHistory.length} RECORDS`);

    if (scanHistory.length === 0) {
        const row = document.createElement("tr");
        row.className = "history-empty-row";

        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.textContent = "> NO SCAN RECORDS AVAILABLE.";

        row.appendChild(cell);
        tbody.appendChild(row);

        return;
    }

    scanHistory.forEach((record) => {
        const row = document.createElement("tr");

        const timeCell = document.createElement("td");
        timeCell.textContent = record.time;

        const urlCell = document.createElement("td");

        const urlSpan = document.createElement("span");
        urlSpan.className = "history-url";
        urlSpan.textContent = record.url;
        urlSpan.title = record.url;

        urlCell.appendChild(urlSpan);

        const verdictCell = document.createElement("td");

        const badge = document.createElement("span");
        badge.className = `history-verdict ${verdictClass(record.verdict)}`;
        badge.textContent = record.verdict;

        verdictCell.appendChild(badge);

        const riskCell = document.createElement("td");
        riskCell.textContent = `${Math.round(record.risk)}/100`;

        const durationCell = document.createElement("td");
        durationCell.textContent = `${record.duration.toFixed(0)} ms`;

        row.append(
            timeCell,
            urlCell,
            verdictCell,
            riskCell,
            durationCell
        );

        tbody.appendChild(row);
    });
}


/* CLEAR HISTORY */

function clearHistory() {
    scanHistory.length = 0;

    sessionStats.total = 0;
    sessionStats.safe = 0;
    sessionStats.threats = 0;
    sessionStats.durations.length = 0;

    lastScanTime = null;

    updateStatistics();
    renderHistory();

    setText("statusLastScan", "NONE");

    setScanMessage("SESSION HISTORY CLEARED.");
}


/* NEWSLETTER */

function setupNewsletter() {
    const form = $("newsletterForm");
    const message = $("newsletterMessage");

    if (!form || !message) {
        return;
    }

    form.addEventListener("submit", (event) => {
        event.preventDefault();

        const emailInput = $("newsletterEmail");

        if (!emailInput || !emailInput.checkValidity()) {
            emailInput?.reportValidity();
            return;
        }

        // No subscription backend is connected.
        // Do not falsely claim that an email was subscribed.
        message.textContent =
            "DEMO ONLY: NO EMAIL WAS SENT OR STORED. A SUBSCRIPTION BACKEND IS NOT CONNECTED.";

        message.style.color = "var(--warning)";
    });
}


/* INITIALIZE */

function initializeCyberGuardian() {
    setupMobileNavigation();

    const scanForm = $("scanForm");

    if (scanForm) {
        scanForm.addEventListener("submit", handleScan);
    }

    const clearButton = $("clearHistoryButton");

    if (clearButton) {
        clearButton.addEventListener("click", clearHistory);
    }

    setupNewsletter();

    updateStatistics();
    renderHistory();

    checkBackend();

    // Recheck backend status periodically.
    setInterval(checkBackend, 10000);
}

document.addEventListener("DOMContentLoaded", initializeCyberGuardian);