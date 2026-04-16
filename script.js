// --- NAVIGATION LOGIC ---
const navDashboard = document.getElementById('nav-dashboard');
const navAnalytics = document.getElementById('nav-analytics');
const navLogs = document.getElementById('nav-logs');

const viewDashboard = document.getElementById('dashboard-view');
const viewAnalytics = document.getElementById('analytics-view');
const viewLogs = document.getElementById('logs-view');

let ratioChartInstance = null; // Store chart instance

function resetViews() {
    navDashboard.classList.remove('active');
    navAnalytics.classList.remove('active');
    navLogs.classList.remove('active');
    viewDashboard.classList.add('hidden');
    viewAnalytics.classList.add('hidden');
    viewLogs.classList.add('hidden');
}

navDashboard.addEventListener('click', () => {
    resetViews();
    navDashboard.classList.add('active');
    viewDashboard.classList.remove('hidden');
});

navAnalytics.addEventListener('click', () => {
    resetViews();
    navAnalytics.classList.add('active');
    viewAnalytics.classList.remove('hidden');
    fetchStatsAndDrawCharts(); // Re-fetch chart stats
});

navLogs.addEventListener('click', () => {
    resetViews();
    navLogs.classList.add('active');
    viewLogs.classList.remove('hidden');
    fetchLogs(); // Reload logs table
});

// --- DASHBOARD API INTEGRATION ---
document.getElementById('analyze-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const url = document.getElementById('url').value.trim();
    const email_body = document.getElementById('email_body').value.trim();
    const sender_name = document.getElementById('sender_name').value.trim();
    const sender_email = document.getElementById('sender_email').value.trim();
    
    const errorMsg = document.getElementById('form-error');
    if (!url && !email_body) {
        errorMsg.classList.remove('hidden');
        return;
    }
    errorMsg.classList.add('hidden');

    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = document.getElementById('loading-spinner');
    const resultsPanel = document.getElementById('results-panel');
    const waitingState = document.getElementById('waiting-state');
    
    submitBtn.disabled = true;
    btnText.textContent = "Processing...";
    spinner.classList.remove('hidden');
    resultsPanel.classList.add('hidden');
    waitingState.classList.remove('hidden');

    try {
        const response = await fetch('http://localhost:8000/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, email_body, sender_name, sender_email })
        });

        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        
        setTimeout(() => {
            displayResults(data);
            waitingState.classList.add('hidden');
            submitBtn.disabled = false;
            btnText.textContent = "Execute Scan";
            spinner.classList.add('hidden');
            if (window.feather) feather.replace(); 
        }, 600);

    } catch (error) {
        console.error('Error:', error);
        alert('API Connection Failed. Ensure Backend is running on port 8000.');
        submitBtn.disabled = false;
        btnText.textContent = "Execute Scan";
        spinner.classList.add('hidden');
        waitingState.classList.remove('hidden');
    }
});

function displayResults(data) {
    const resultsPanel = document.getElementById('results-panel');
    const resultCard = document.getElementById('result-card');
    const statusRing = document.getElementById('status-ring');
    const predictionText = document.getElementById('prediction-text');
    const confidenceScore = document.getElementById('confidence-score');
    const explanationText = document.getElementById('explanation-text');
    const meterFill = document.getElementById('meter-fill');

    resultsPanel.classList.remove('hidden');
    
    resultCard.className = "result-details";
    statusRing.className = "icon-ring";

    let iconName = "check";
    let score = data.prediction === 1 ? data.malicious_confidence : data.safe_confidence;
    meterFill.style.width = `${score}%`;

    if (data.prediction === 1) { 
        resultCard.classList.add('state-malicious');
        statusRing.classList.add('bg-danger');
        iconName = "alert-triangle";
        predictionText.textContent = "MALICIOUS";
        confidenceScore.textContent = `${score}%`;
        meterFill.className = "meter-bar-fill bg-danger";
    } else { 
        if (data.malicious_confidence > 30) {
            resultCard.classList.add('state-warning');
            statusRing.classList.add('bg-warning');
            iconName = "alert-circle";
            predictionText.textContent = "SUSPICIOUS";
            confidenceScore.textContent = `${score}%`;
            meterFill.className = "meter-bar-fill bg-warning";
        } else {
            resultCard.classList.add('state-safe');
            statusRing.classList.add('bg-success');
            iconName = "shield";
            predictionText.textContent = "SAFE";
            confidenceScore.textContent = `${score}%`;
            meterFill.className = "meter-bar-fill bg-success";
        }
    }

    statusRing.innerHTML = `<i data-feather="${iconName}" id="status-icon"></i>`;
    explanationText.innerHTML = `${data.explanation}`;
}

// --- ANALYTICS API (Chart.js) INTEGRATION ---
async function fetchStatsAndDrawCharts() {
    try {
        const response = await fetch('http://localhost:8000/api/stats');
        const stats = await response.json();

        // Update Total Score component
        document.getElementById('total-stat').textContent = stats.total;

        const noDataMsg = document.getElementById('no-data-msg');
        if (stats.total === 0) {
            noDataMsg.style.display = 'block';
            return;
        } else {
            noDataMsg.style.display = 'none';
        }

        const ctx = document.getElementById('ratioChart').getContext('2d');
        
        // Destroy old chart to prevent overlap glitching
        if (ratioChartInstance) { ratioChartInstance.destroy(); }

        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Inter', sans-serif";

        ratioChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Scans', 'Malicious Scans'],
                datasets: [{
                    data: [stats.safe_count, stats.malicious_count],
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.8)', // Success Green
                        'rgba(239, 68, 68, 0.8)'   // Danger Red
                    ],
                    borderColor: '#1e293b',
                    borderWidth: 3,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { position: 'bottom', labels: { padding: 20 } }
                },
                animation: { animateScale: true, animateRotate: true }
            }
        });

    } catch(err) {
        console.error("Failed to load chart stats. Is backend API running?", err);
    }
}

// --- SCAN LOGS API INTEGRATION ---
async function fetchLogs() {
    const tbody = document.getElementById('logs-tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading telemetry...</td></tr>';
    
    try {
        const response = await fetch('http://localhost:8000/api/logs');
        if (!response.ok) throw new Error('API failure');
        const logs = await response.json();
        
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No scan records found. Run a scan to generate telemetry.</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        logs.forEach(log => {
            const badgeClass = log.prediction === 'Safe' ? 'badge-safe' : 'badge-malicious';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="color: var(--text-muted); font-size: 0.85rem;">${log.timestamp}</td>
                <td style="word-break: break-all; max-width: 250px;">${log.target}</td>
                <td><span class="badge ${badgeClass}">${log.prediction}</span></td>
                <td style="font-weight: 600;">${log.confidence}</td>
                <td style="color: #cbd5e1; font-size: 0.85rem;">${log.reason}</td>
            `;
            tbody.appendChild(tr);
        });
        
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load telemetry data.</td></tr>';
    }
}
