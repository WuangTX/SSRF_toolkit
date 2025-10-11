// WebSocket connection
const socket = io();

// State
let scanState = {
    isRunning: false,
    startTime: null,
    timerInterval: null
};

let currentFilter = 'all';

// DOM Elements
const scanForm = document.getElementById('scanForm');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const resetBtn = document.getElementById('resetBtn');
const exportBtn = document.getElementById('exportBtn');
const statusBadge = document.getElementById('statusBadge');
const progressPanel = document.getElementById('progressPanel');
const currentPhase = document.getElementById('currentPhase');
const progressPercent = document.getElementById('progressPercent');
const progressFill = document.getElementById('progressFill');
const findingsCount = document.getElementById('findingsCount');
const elapsedTime = document.getElementById('elapsedTime');
const findingsList = document.getElementById('findingsList');
const consoleDiv = document.getElementById('console');
const clearConsoleBtn = document.getElementById('clearConsoleBtn');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    checkScanStatus();
});

// Event Listeners
function setupEventListeners() {
    // Form submission
    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        startScan();
    });

    // Stop button
    stopBtn.addEventListener('click', stopScan);

    // Reset button
    resetBtn.addEventListener('click', resetScan);

    // Export button
    exportBtn.addEventListener('click', exportReport);

    // Clear console
    clearConsoleBtn.addEventListener('click', clearConsole);

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const filter = e.currentTarget.dataset.filter;
            setFilter(filter);
        });
    });

    // WebSocket events
    socket.on('connected', (data) => {
        addConsoleLog('info', data.message);
    });

    socket.on('log', (data) => {
        addConsoleLog(data.level, data.message);
        if (data.level === 'finding') {
            addFinding(data);
        }
    });

    socket.on('progress', (data) => {
        updateProgress(data.phase, data.progress);
    });
}

// Start Scan
async function startScan() {
    const formData = new FormData(scanForm);
    const data = {
        mode: formData.get('mode'),
        target: formData.get('target'),
        source_path: formData.get('source_path'),
        timeout: parseInt(formData.get('timeout')),
        endpoint_discovery: formData.get('endpoint_discovery') === 'on',
        parameter_fuzzing: formData.get('parameter_fuzzing') === 'on',
        callback_testing: formData.get('callback_testing') === 'on',
        internal_scanning: formData.get('internal_scanning') === 'on',
        docker_inspection: formData.get('docker_inspection') === 'on',
        code_scanning: formData.get('code_scanning') === 'on'
    };

    try {
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            scanState.isRunning = true;
            scanState.startTime = Date.now();
            updateUIForScanStart();
            startTimer();
            addConsoleLog('info', '🚀 Scan started successfully');
        } else {
            addConsoleLog('error', `❌ Failed to start scan: ${result.error}`);
        }
    } catch (error) {
        addConsoleLog('error', `❌ Error: ${error.message}`);
    }
}

// Stop Scan
async function stopScan() {
    try {
        const response = await fetch('/api/scan/stop', {
            method: 'POST'
        });

        const result = await response.json();

        if (response.ok) {
            scanState.isRunning = false;
            updateUIForScanStop();
            stopTimer();
            addConsoleLog('warning', '⏹️ Scan stopped by user');
        } else {
            addConsoleLog('error', `❌ Failed to stop scan: ${result.error}`);
        }
    } catch (error) {
        addConsoleLog('error', `❌ Error: ${error.message}`);
    }
}

// Reset Scan State
async function resetScan() {
    if (confirm('Are you sure you want to reset the scan state? This will unlock any stuck scans.')) {
        try {
            const response = await fetch('/api/scan/reset', {
                method: 'POST'
            });

            const result = await response.json();

            if (response.ok) {
                scanState.isRunning = false;
                updateUIForScanStop();
                stopTimer();
                addConsoleLog('info', '🔄 Scan state reset successfully');
                
                // Reset UI completely
                progressPanel.style.display = 'none';
                currentPhase.textContent = 'Initializing...';
                progressPercent.textContent = '0%';
                progressFill.style.width = '0%';
            } else {
                addConsoleLog('error', `❌ Failed to reset: ${result.error}`);
            }
        } catch (error) {
            addConsoleLog('error', `❌ Error: ${error.message}`);
        }
    }
}

// Export Report
async function exportReport() {
    try {
        const response = await fetch('/api/report/export', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ format: 'json' })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ssrf_report_${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            addConsoleLog('info', '📥 Report exported successfully');
        } else {
            addConsoleLog('error', '❌ Failed to export report');
        }
    } catch (error) {
        addConsoleLog('error', `❌ Error: ${error.message}`);
    }
}

// Check Scan Status
async function checkScanStatus() {
    try {
        const response = await fetch('/api/scan/status');
        const status = await response.json();

        if (status.is_running) {
            scanState.isRunning = true;
            scanState.startTime = new Date(status.start_time).getTime();
            updateUIForScanStart();
            startTimer();
        }
    } catch (error) {
        console.error('Failed to check scan status:', error);
    }
}

// Update UI for scan start
function updateUIForScanStart() {
    startBtn.disabled = true;
    stopBtn.disabled = false;
    progressPanel.style.display = 'block';
    statusBadge.innerHTML = '<i class="fas fa-circle"></i> Scanning';
    statusBadge.classList.add('scanning');
    
    // Clear previous findings
    findingsList.innerHTML = '';
    resetFindingsCounts();
}

// Update UI for scan stop
function updateUIForScanStop() {
    startBtn.disabled = false;
    stopBtn.disabled = true;
    statusBadge.innerHTML = '<i class="fas fa-circle"></i> Ready';
    statusBadge.classList.remove('scanning');
}

// Update Progress
function updateProgress(phase, progress) {
    currentPhase.textContent = phase;
    progressPercent.textContent = `${progress}%`;
    progressFill.style.width = `${progress}%`;

    if (progress >= 100) {
        scanState.isRunning = false;
        updateUIForScanStop();
        stopTimer();
    }
}

// Add Finding
function addFinding(data) {
    const finding = document.createElement('div');
    finding.className = `finding-item ${data.severity}`;
    finding.dataset.severity = data.severity;
    
    finding.innerHTML = `
        <div class="finding-header">
            <span class="badge badge-${data.severity.toLowerCase()}">${data.severity}</span>
            <span class="finding-timestamp">${data.timestamp || new Date().toLocaleTimeString()}</span>
        </div>
        <div class="finding-message">${data.message}</div>
    `;

    // Remove empty state if exists
    const emptyState = findingsList.querySelector('.empty-state');
    if (emptyState) {
        emptyState.remove();
    }

    findingsList.insertBefore(finding, findingsList.firstChild);
    
    // Update counters
    updateFindingsCounts();
    
    // Apply current filter
    applyFilter();
}

// Update Findings Counts
function updateFindingsCounts() {
    const findings = findingsList.querySelectorAll('.finding-item');
    const counts = {
        all: findings.length,
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };

    findings.forEach(finding => {
        const severity = finding.dataset.severity;
        if (counts[severity] !== undefined) {
            counts[severity]++;
        }
    });

    document.getElementById('countAll').textContent = counts.all;
    document.getElementById('countCritical').textContent = counts.CRITICAL;
    document.getElementById('countHigh').textContent = counts.HIGH;
    document.getElementById('countMedium').textContent = counts.MEDIUM;
    document.getElementById('countLow').textContent = counts.LOW;
    
    findingsCount.textContent = counts.all;
}

// Reset Findings Counts
function resetFindingsCounts() {
    document.getElementById('countAll').textContent = '0';
    document.getElementById('countCritical').textContent = '0';
    document.getElementById('countHigh').textContent = '0';
    document.getElementById('countMedium').textContent = '0';
    document.getElementById('countLow').textContent = '0';
    findingsCount.textContent = '0';
}

// Set Filter
function setFilter(filter) {
    currentFilter = filter;
    
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        }
    });

    applyFilter();
}

// Apply Filter
function applyFilter() {
    const findings = findingsList.querySelectorAll('.finding-item');
    
    findings.forEach(finding => {
        if (currentFilter === 'all' || finding.dataset.severity === currentFilter) {
            finding.style.display = 'block';
        } else {
            finding.style.display = 'none';
        }
    });
}

// Add Console Log
function addConsoleLog(level, message) {
    const line = document.createElement('div');
    line.className = `console-line ${level}`;
    
    const timestamp = new Date().toLocaleTimeString();
    
    line.innerHTML = `
        <span class="timestamp">${timestamp}</span>
        <span class="message">${escapeHtml(message)}</span>
    `;

    consoleDiv.appendChild(line);
    consoleDiv.scrollTop = consoleDiv.scrollHeight;
}

// Clear Console
function clearConsole() {
    consoleDiv.innerHTML = `
        <div class="console-line info">
            <span class="timestamp">${new Date().toLocaleTimeString()}</span>
            <span class="message">Console cleared</span>
        </div>
    `;
}

// Timer
function startTimer() {
    if (scanState.timerInterval) {
        clearInterval(scanState.timerInterval);
    }

    scanState.timerInterval = setInterval(() => {
        if (scanState.startTime) {
            const elapsed = Date.now() - scanState.startTime;
            const minutes = Math.floor(elapsed / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            elapsedTime.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }
    }, 1000);
}

function stopTimer() {
    if (scanState.timerInterval) {
        clearInterval(scanState.timerInterval);
        scanState.timerInterval = null;
    }
}

// Utility Functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Keyboard Shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to start scan
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (!scanState.isRunning) {
            startScan();
        }
    }
    
    // Escape to stop scan
    if (e.key === 'Escape') {
        if (scanState.isRunning) {
            stopScan();
        }
    }
});
