let fullReport = "";
let barChart = null;
let pieChart = null;
let liveFeedInterval = null;
let currentScan = null;
let currentAIAnalysis = "";
let emailSharePayload = null;

const RECEIVER_EMAILS_KEY = "sentinelReceiverEmails";
const LAST_RECEIVER_KEY = "sentinelLastReceiverEmail";

const CHART_COLORS = ['#10b981', '#3b82f6', '#8b5cf6', '#f59e0b', '#ef4444'];

window.onload = () => {
  const theme = localStorage.getItem("theme");
  if (theme === "light") document.body.classList.add("light");
};

document.addEventListener("DOMContentLoaded", () => {
  const urlInput = document.getElementById("url");
  populateEmailSuggestions();
  const downloadBtn = document.getElementById("downloadAIBtn");
  if (downloadBtn) {
    downloadBtn.addEventListener("click", downloadAIText);
  }
  
  if (urlInput) {
      urlInput.addEventListener("keypress", (event) => {
        if (event.key === "Enter") {
          event.preventDefault(); // Prevent form submission if inside a form
          startScan();
        }
      });
  }

  document.addEventListener("click", (event) => {
    const menu = document.getElementById("scanShareMenu");
    const btn = document.getElementById("scanShareMenuBtn");
    if (!menu || !btn) return;
    if (!menu.contains(event.target) && !btn.contains(event.target)) {
      menu.classList.add("hidden");
    }
  });
});

function readStoredEmailList(key) {
  try {
    const raw = localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

function upsertStoredEmail(key, email) {
  const normalized = (email || "").trim().toLowerCase();
  if (!normalized) return;
  const current = readStoredEmailList(key).filter((item) => item !== normalized);
  current.unshift(normalized);
  localStorage.setItem(key, JSON.stringify(current.slice(0, 8)));
}

function fillDatalist(listId, values) {
  const listEl = document.getElementById(listId);
  if (!listEl) return;
  listEl.innerHTML = values.map((value) => `<option value="${value}"></option>`).join("");
}

function populateEmailSuggestions() {
  fillDatalist("receiverEmailSuggestions", readStoredEmailList(RECEIVER_EMAILS_KEY));
}

// ─── Tab Switching ───
function switchTab(tab) {
  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

  document.getElementById(`tab-${tab}`).classList.remove('hidden');

  const btnId = tab === 'terminal' ? 'tabBtnTerminal' : 'tabBtnVisuals';
  document.getElementById(btnId).classList.add('active');

  if (tab === 'visuals') {
    setTimeout(renderCharts, 100);
  }
}

// ─── Chart View Toggle (Bar / Pie) ───
function toggleChartView(type) {
  const barWrapper = document.getElementById('barWrapper');
  const pieWrapper = document.getElementById('pieWrapper');
  const btns = document.querySelectorAll('.toggle-btn');

  if (type === 'bar') {
    barWrapper.classList.remove('hidden');
    pieWrapper.classList.add('hidden');
    btns[0].classList.add('active');
    btns[1].classList.remove('active');
  } else {
    pieWrapper.classList.remove('hidden');
    barWrapper.classList.add('hidden');
    btns[1].classList.add('active');
    btns[0].classList.remove('active');
  }
}

// ─── Scan ───
async function startScan() {
  const url = document.getElementById("url").value.trim();
  const output = document.getElementById("output");
  const progress = document.getElementById("progress");
  const fill = progress.querySelector('.progress-fill');
  const scanBtn = document.getElementById("scanBtn");

  if (!url) {
    output.textContent = "[!] Error: No target URL provided.";
    return;
  }

  // Reset state
  fullReport = "";
  currentScan = null;
  currentAIAnalysis = "";
  document.querySelectorAll('.scan-action-btn').forEach(btn => btn.classList.remove('visible'));
  scanBtn.disabled = true;
  scanBtn.querySelector('.btn-text').textContent = "Scanning...";

  progress.classList.remove("hidden");
  fill.style.width = "0%";

  setTimeout(() => fill.style.width = "20%", 100);
  setTimeout(() => fill.style.width = "45%", 1500);

  output.textContent =
    `[SYSTEM] Booting scanning engine...\n` +
    `[SYSTEM] Loading scanner_pro.py modules...\n` +
    `[SYSTEM] Initializing Playwright browser...\n` +
    `[SYSTEM] Connecting to target: ${url}\n`;

  // Setup and start Live Feed polling
  const liveFeedImg = document.getElementById("liveFeed");
  const placeholder = document.getElementById("liveFeedPlaceholder");
  
  if (liveFeedImg && placeholder) {
      liveFeedImg.classList.remove("hidden");
      placeholder.classList.add("hidden");

      if (liveFeedInterval) clearInterval(liveFeedInterval);

      // Fetch the latest screenshot every 1 second
      liveFeedInterval = setInterval(() => {
        liveFeedImg.src = `http://127.0.0.1:5001/static/live/live_view.png?t=${new Date().getTime()}`;
      }, 1000);
  }

  try {
    const res = await fetch("http://127.0.0.1:5001/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    fill.style.width = "85%";
    const data = await res.json();
    fill.style.width = "100%";

    if (liveFeedInterval) clearInterval(liveFeedInterval);

    if (data.error) {
      output.textContent += `\n[FATAL ERROR] ${data.error}`;
    } else {
      fullReport = data.report;
      currentScan = {
        id: data.scan_id,
        url: data.url || url,
        video: data.video || "",
        report: data.report
      };
      output.textContent = fullReport;
      document.querySelectorAll('.scan-action-btn').forEach(btn => btn.classList.add('visible'));
    }
  } catch (err) {
    if (liveFeedInterval) clearInterval(liveFeedInterval);
    output.textContent +=
      `\n[FATAL ERROR] Backend (app.py) not responding on port 5001.\n` +
      `[TIP] Run: python app.py`;
    fill.style.width = "100%";
  }

  setTimeout(() => {
    progress.classList.add("hidden");
    fill.style.width = "0%";
    scanBtn.disabled = false;
    scanBtn.querySelector('.btn-text').textContent = "Initialize Scan";
  }, 1500);
}

function toggleScanShareMenu(event) {
  event.stopPropagation();
  const menu = document.getElementById("scanShareMenu");
  if (!menu) return;
  menu.classList.toggle("hidden");
}

function openEmailModalFromScan() {
  if (!fullReport) {
    alert("Please perform a scan first.");
    return;
  }

  emailSharePayload = {
    report_raw: fullReport,
    subject: `Sentinel Security Report${currentScan?.id ? ` - ${currentScan.id}` : ""}`,
    ai_analysis: currentAIAnalysis || ""
  };

  openEmailModal();
}

function openEmailModal() {
  const modal = document.getElementById("emailShareModal");
  const status = document.getElementById("emailShareStatus");
  const receiverInput = document.getElementById("receiverEmailInput");
  const lastReceiver = localStorage.getItem(LAST_RECEIVER_KEY) || "";
  
  if (!modal) return;
  if (status) status.textContent = "";
  
  populateEmailSuggestions();
  if (receiverInput) receiverInput.value = lastReceiver;
  modal.classList.remove("hidden");
}

function closeEmailModal() {
  const modal = document.getElementById("emailShareModal");
  if (modal) modal.classList.add("hidden");
}

async function sendShareEmail() {
  if (!emailSharePayload) {
    alert("Nothing to share yet.");
    return;
  }

  const receiver = document.getElementById("receiverEmailInput")?.value.trim();
  const status = document.getElementById("emailShareStatus");

  if (!receiver) {
    if (status) status.textContent = "Please enter the recipient email.";
    return;
  }

  upsertStoredEmail(RECEIVER_EMAILS_KEY, receiver);
  localStorage.setItem(LAST_RECEIVER_KEY, receiver);
  populateEmailSuggestions();

  if (status) status.textContent = "Sending email...";

  try {
    const res = await fetch("http://127.0.0.1:5001/share/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender_email: "system@sentinel.local", // Bypass backend 400 validation error
        receiver_email: receiver,
        ...emailSharePayload
      })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      if (status) status.textContent = `Error: ${data.error || "Failed to send email"}`;
      return;
    }

    if (status) status.textContent = "Email sent successfully.";
  } catch (err) {
    if (status) status.textContent = "Failed to send email. Check backend and API keys.";
  }
}

function downloadReportText() {
  if (!fullReport) {
    alert("Please perform a scan first.");
    return;
  }

  const blob = new Blob([fullReport], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel_report_${currentScan?.id || "latest"}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function shareToWhatsAppFromScan() {
  if (!fullReport) {
    alert("Please perform a scan first.");
    return;
  }
  const text = `Sentinel Scan Report\nTarget: ${currentScan?.url || "N/A"}\nThreats found. Check details in attached/log export.`;
  window.open(`https://wa.me/?text=${encodeURIComponent(text)}`, "_blank");
}

async function shareNativeFromScan() {
  if (!fullReport) {
    alert("Please perform a scan first.");
    return;
  }

  const text = `Sentinel security scan for ${currentScan?.url || "target"} is ready.`;
  if (navigator.share) {
    try {
      await navigator.share({
        title: "Sentinel Security Report",
        text
      });
    } catch (_) {
      // user cancelled
    }
    return;
  }

  alert("Native sharing is not supported in this browser. Use Mail, WhatsApp, or Download instead.");
}

async function openAIHelp() {
  if (!fullReport) {
    alert("Please perform a scan first.");
    return;
  }

  const modal = document.getElementById("aiHelpModal");
  const content = document.getElementById("aiHelpContent");
  const downloadBtn = document.getElementById("downloadAIBtn");
  if (!modal || !content) return;

  modal.classList.remove("hidden");
  content.textContent = "Analyzing vulnerabilities with AI...";
  if (downloadBtn) downloadBtn.classList.add("hidden");

  try {
    const res = await fetch("http://127.0.0.1:5001/ai-help", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_raw: fullReport })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      content.textContent = `AI Help Error: ${data.error || "Unable to fetch analysis"}`;
      return;
    }

    currentAIAnalysis = data.analysis || "No analysis returned.";
    content.textContent = currentAIAnalysis;
    if (downloadBtn) downloadBtn.classList.remove("hidden");
  } catch (err) {
    content.textContent = "AI Help failed. Ensure backend is running and GROQ_API_KEY is configured.";
    if (downloadBtn) downloadBtn.classList.add("hidden");
  }
}

function closeAIHelpModal() {
  const modal = document.getElementById("aiHelpModal");
  const downloadBtn = document.getElementById("downloadAIBtn");
  if (modal) modal.classList.add("hidden");
  if (downloadBtn) downloadBtn.classList.add("hidden");
}

function downloadAIText() {
  const modalContent = document.getElementById("aiHelpContent");
  const textToSave = (currentAIAnalysis || modalContent?.textContent || "").trim();

  if (!textToSave || textToSave === "Analyzing vulnerabilities with AI...") {
    alert("No AI analysis available to download.");
    return;
  }

  const targetName = currentScan?.url || currentScan?.id || "latest";
  const filename = `Sentinel_AI_Advice_${targetName.replace(/[^a-z0-9._-]+/gi, "_")}.txt`;
  const blob = new Blob([textToSave], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ─── OWASP Data Parser ───
function getOWASPData() {
  const counts = {};
  fullReport.split("\n").forEach(line => {
    if (line.includes("OWASP")) {
      const match = line.match(/(A\d{2})\s*-\s*([^:]+)/);
      if (match) {
        // Short label: "A03 - Injection"
        const label = `${match[1]} - ${match[2].trim()}`;
        counts[label] = (counts[label] || 0) + 1;
      }
    }
  });
  return { labels: Object.keys(counts), values: Object.values(counts) };
}

// ─── Render Charts ───
function renderCharts() {
  if (!fullReport) return;
  const { labels, values } = getOWASPData();
  if (!labels.length) return;

  const isDark = !document.body.classList.contains('light');
  const textColor = isDark ? '#f8fafc' : '#0f172a';
  const gridColor = isDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.07)';

  // ── Bar Chart ──
  if (barChart) barChart.destroy();
  barChart = new Chart(document.getElementById("owaspBar"), {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Issues Found",
        data: values,
        backgroundColor: CHART_COLORS.slice(0, labels.length),
        borderRadius: 8,
        borderSkipped: false,
      }]
    },
    options: {
      animation: { duration: 600 },
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.y} issue(s)` } }
      },
      scales: {
        x: {
          ticks: { color: textColor, font: { size: 10 } },
          grid: { display: false },
          border: { color: gridColor }
        },
        y: {
          ticks: { color: textColor, stepSize: 1 },
          grid: { color: gridColor },
          border: { color: gridColor }
        }
      }
    }
  });

  // ── Doughnut Chart ──
  if (pieChart) pieChart.destroy();
  pieChart = new Chart(document.getElementById("owaspPie"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: CHART_COLORS.slice(0, labels.length),
        borderWidth: 2,
        borderColor: isDark ? '#0f172a' : '#f8fafc',
        hoverOffset: 8
      }]
    },
    options: {
      animation: { duration: 600 },
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: textColor,
            padding: 14,
            font: { size: 11 },
            usePointStyle: true
          }
        }
      }
    }
  });
}

// ─── PDF Export ───
async function downloadPDF() {
  if (!fullReport) {
    alert("Please perform a scan first!");
    return;
  }

  const visualsTab  = document.getElementById('tab-visuals');
  const barWrapper  = document.getElementById('barWrapper');
  const pieWrapper  = document.getElementById('pieWrapper');

  // Remember original visibility state
  const tabWasHidden = visualsTab.classList.contains('hidden');
  const barWasHidden = barWrapper.classList.contains('hidden');
  const pieWasHidden = pieWrapper.classList.contains('hidden');

  // Force BOTH chart wrappers and the tab visible so canvases have real dimensions
  visualsTab.classList.remove('hidden');
  barWrapper.classList.remove('hidden');
  pieWrapper.classList.remove('hidden');

  // Destroy & re-render so Chart.js sizes into the now-visible canvases
  if (barChart) { barChart.destroy(); barChart = null; }
  if (pieChart) { pieChart.destroy(); pieChart = null; }
  renderCharts();

  // Give Chart.js one animation frame + a small buffer to paint
  await new Promise(r => requestAnimationFrame(() => setTimeout(r, 400)));

  setTimeout(async () => {
    let barB64 = null;
    let pieB64 = null;

    try {
      barB64 = document.getElementById("owaspBar").toDataURL("image/png");
      pieB64 = document.getElementById("owaspPie").toDataURL("image/png");
    } catch (e) {
      console.warn("Chart capture failed:", e);
    }

    // Restore original visibility
    if (tabWasHidden) visualsTab.classList.add('hidden');
    if (barWasHidden) barWrapper.classList.add('hidden');
    if (pieWasHidden) pieWrapper.classList.add('hidden');

    try {
      const response = await fetch("http://127.0.0.1:5001/download-pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report_raw: fullReport, barChart: barB64, pieChart: pieB64 })
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = "Sentinel_Security_Audit.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        const err = await response.json();
        alert("PDF Error: " + (err.error || "Unknown error"));
      }
    } catch (err) {
      alert("PDF generation failed. Ensure app.py is running.");
      console.error(err);
    }
  }, 500);
}

// ─── Theme Toggle ───
function toggleTheme() {
  document.body.classList.toggle("light");
  localStorage.setItem("theme", document.body.classList.contains("light") ? "light" : "dark");
  if (!document.getElementById('tab-visuals').classList.contains('hidden')) {
    renderCharts();
  }
}

// ─── Log Filter / Search ───
function searchOutput() {
  const query = document.getElementById("search").value.toLowerCase().trim();
  const output = document.getElementById("output");

  if (!fullReport) return;

  if (!query) {
    output.textContent = fullReport;
    return;
  }

  output.innerHTML = "";
  let matchCount = 0;
  fullReport.split("\n").forEach(line => {
    if (line.toLowerCase().includes(query)) {
      const div = document.createElement("div");
      div.textContent = line;
      div.style.background = "rgba(16, 185, 129, 0.12)";
      div.style.borderLeft = "3px solid #10b981";
      div.style.paddingLeft = "6px";
      div.style.marginBottom = "2px";
      output.appendChild(div);
      matchCount++;
    }
  });

  if (matchCount === 0) {
    output.textContent = `[SEARCH] No results for "${query}"`;
  }
} 