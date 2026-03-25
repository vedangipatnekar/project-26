let fullReport = "";
let barChart = null;
let pieChart = null;

const CHART_COLORS = ['#10b981', '#3b82f6', '#8b5cf6', '#f59e0b', '#ef4444'];

window.onload = () => {
  const theme = localStorage.getItem("theme");
  if (theme === "light") document.body.classList.add("light");
};

document.addEventListener("DOMContentLoaded", () => {
  const urlInput = document.getElementById("url");
  
  urlInput.addEventListener("keypress", (event) => {
    if (event.key === "Enter") {
      event.preventDefault(); // Prevent form submission if inside a form
      startScan();
    }
  });
});

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
  document.querySelector('.secondary-btn').classList.remove('visible');
  scanBtn.disabled = true;
  scanBtn.querySelector('.btn-text').textContent = "Scanning...";

  progress.classList.remove("hidden");
  fill.style.width = "0%";

  setTimeout(() => fill.style.width = "20%", 100);
  setTimeout(() => fill.style.width = "45%", 1500);

  output.textContent =
    `[SYSTEM] Booting scanning engine...\n` +
    `[SYSTEM] Loading scanner.py modules...\n` +
    `[SYSTEM] Initializing request session...\n` +
    `[SYSTEM] Connecting to target: ${url}\n`;

  try {
    const res = await fetch("http://127.0.0.1:5001/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    fill.style.width = "85%";
    const data = await res.json();
    fill.style.width = "100%";

    if (data.error) {
      output.textContent += `\n[FATAL ERROR] ${data.error}`;
    } else {
      fullReport = data.report;
      output.textContent = fullReport;
      // ✅ Reveal Export button only after a successful scan
      document.querySelector('.secondary-btn').classList.add('visible');
    }
  } catch (err) {
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
        body: JSON.stringify({ barChart: barB64, pieChart: pieB64 })
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