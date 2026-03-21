/* ================================
   LOAD SAVED THEME
================================ */
window.onload = () => {
  const theme = localStorage.getItem("theme");
  if (theme === "light") {
    document.body.classList.add("light");
  }
};

/* ================================
   GLOBAL STATE
================================ */
let fullReport = "";
let barChart = null;
let pieChart = null;

/* ================================
   HELPER: AUTO SCROLL
================================ */
function scrollToBottom() {
  const output = document.getElementById("output");
  output.scrollTop = output.scrollHeight;
}

/* ================================
   START SCAN
================================ */
async function startScan() {
  const url = document.getElementById("url").value;
  const output = document.getElementById("output");
  const progress = document.getElementById("progress");

  if (!url) {
    output.textContent = "❌ Please enter a URL";
    return;
  }

  progress.classList.remove("hidden");
  output.textContent = `🔍 Scanning ${url}...\n\nPlease wait...`;
  scrollToBottom();

  try {
    const res = await fetch("http://127.0.0.1:5001/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    if (data.error) {
      output.textContent = "❌ Error:\n" + data.error;
    } else {
      fullReport = data.report;
      output.textContent = fullReport;
      scrollToBottom();
    }
  } catch (err) {
    output.textContent = "❌ Backend not reachable";
  }

  progress.classList.add("hidden");
}

/* ================================
   SEARCH INSIDE OUTPUT
================================ */
function searchOutput() {
  const query = document.getElementById("search").value.toLowerCase();
  const output = document.getElementById("output");

  if (!query) {
    output.textContent = fullReport;
    scrollToBottom();
    return;
  }

  output.innerHTML = "";

  fullReport.split("\n").forEach(line => {
    if (line.toLowerCase().includes(query)) {
      const div = document.createElement("div");
      div.textContent = line;
      div.style.background = "rgba(255,255,0,0.15)";
      output.appendChild(div);
    }
  });
}

/* ================================
   THEME TOGGLE
================================ */
function toggleTheme() {
  document.body.classList.toggle("light");
  localStorage.setItem(
    "theme",
    document.body.classList.contains("light") ? "light" : "dark"
  );
}

/* ================================
   SHOW OWASP CHARTS
================================ */
function getOWASPData() {
  const counts = {};

  fullReport.split("\n").forEach(line => {
    if (line.includes("OWASP")) {
      const match = line.match(/(A\d{2}\s*-\s*.*)/);
      if (match) {
        const fullLabel = match[1].trim();
        counts[fullLabel] = (counts[fullLabel] || 0) + 1;
      }
    }
  });

  return {
    labels: Object.keys(counts),
    values: Object.values(counts)
  };
}

function showBarChart() {
  if (!fullReport) return;

  const { labels, values } = getOWASPData();

  document.getElementById("barContainer").classList.remove("hidden");
  document.getElementById("pieContainer").classList.add("hidden");

  if (barChart) barChart.destroy();

  const colors = [
  "#ef4444", // red
  "#f97316", // orange
  "#eab308", // yellow
  "#22c55e", // green
  "#06b6d4", // cyan
  "#3b82f6", // blue
  "#8b5cf6", // purple
  "#ec4899", // pink
  "#14b8a6", // teal
  "#64748b"  // gray
];

barChart = new Chart(document.getElementById("owaspBar"), {
  type: "bar",
  data: {
    labels,
    datasets: [{
      data: values,
      backgroundColor: labels.map((_, index) => colors[index % colors.length])
    }]
  },
  options: {
    plugins: {
      legend: { display: false }
    },
    scales: {
      x: {
        ticks: { color: "#ffffff" }
      },
      y: {
        ticks: { color: "#ffffff" }
      }
    }
  }
});
}

function showPieChart() {
  if (!fullReport) return;

  const { labels, values } = getOWASPData();

  document.getElementById("pieContainer").classList.remove("hidden");
  document.getElementById("barContainer").classList.add("hidden");

  if (pieChart) pieChart.destroy();

  pieChart = new Chart(document.getElementById("owaspPie"), {
    type: "pie",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: [
          "#ef4444",
          "#f97316",
          "#eab308",
          "#22c55e",
          "#06b6d4",
          "#3b82f6",
          "#8b5cf6",
          "#ec4899"
        ]
      }]
    },
    plugins: [ChartDataLabels],
    options: {
      plugins: {
        legend: { position: "bottom" },
        datalabels: {
          color: "#ffffff",
          font: { weight: "bold" },
          formatter: function(value, context) {
            const label = context.chart.data.labels[context.dataIndex];
            return label + "\n" + value;
          }
        }
      }
    }
  });
}



/* ================================
   PDF PREVIEW
================================ */
function downloadPDF() {
  window.location.href = "http://127.0.0.1:5001/download-pdf";
}

