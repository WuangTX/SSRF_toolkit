// Initialize socket
const socket = io();

// DOM Elements
const scanForm = document.getElementById('scanForm');
const startBtn = document.getElementById('startBtn');
const configSection = document.getElementById('configSection');
const resultsSection = document.getElementById('resultsSection');
const autoDiscovery = document.getElementById('autoDiscovery');
const manualTests = document.getElementById('manualTests');
const backBtn = document.getElementById('backBtn');
const stopBtn = document.getElementById('stopBtn');
const exportBtn = document.getElementById('exportBtn');
const notifications = document.getElementById('notifications');

// Stats
const statEndpoints = document.getElementById('statEndpoints');
const statParams = document.getElementById('statParams');
const statFindings = document.getElementById('statFindings');
const statCritical = document.getElementById('statCritical');

// Progress
const progressFill = document.getElementById('progressFill');
const progressPhase = document.getElementById('progressPhase');
const progressTime = document.getElementById('progressTime');

// Lists
const logsList = document.getElementById('logsList');
const endpointsList = document.getElementById('endpointsList');
const findingsList = document.getElementById('findingsList');

// State
let startTime = Date.now();
// Use a single global timer handle to avoid duplicate timers across templates/scripts
window.ssrfTimerInterval = window.ssrfTimerInterval || null;
let counts = {
    endpoints: 0,
    params: 0,
    findings: 0,
    critical: 0
};

// Config Tabs Switching
document.querySelectorAll('.config-tab').forEach(tab => {
    tab.addEventListener('click', function() {
        // Remove active from all config tabs
        document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.config-tab-content').forEach(c => c.classList.remove('active'));
        
        // Add active to clicked
        this.classList.add('active');
        const tabName = this.dataset.configTab;
        document.getElementById(tabName + 'Tab').classList.add('active');
    });
});

// File Upload Handling
const fileUploadArea = document.getElementById('fileUploadArea');
const burpFile = document.getElementById('burpFile');
const fileSelected = document.getElementById('fileSelected');
const fileName = document.getElementById('fileName');
const removeFile = document.getElementById('removeFile');

// Click to upload
fileUploadArea.addEventListener('click', function(e) {
    if (e.target !== removeFile) {
        burpFile.click();
    }
});

// File selected
burpFile.addEventListener('change', function() {
    if (this.files.length > 0) {
        fileName.textContent = this.files[0].name;
        fileSelected.style.display = 'flex';
        fileUploadArea.style.borderColor = '#28a745';
        fileUploadArea.style.background = '#f0fff4';
    }
});

// Remove file
removeFile.addEventListener('click', function(e) {
    e.stopPropagation();
    burpFile.value = '';
    fileSelected.style.display = 'none';
    fileUploadArea.style.borderColor = '#d0d0d0';
    fileUploadArea.style.background = '#fafafa';
});

// Drag and drop
fileUploadArea.addEventListener('dragover', function(e) {
    e.preventDefault();
    this.classList.add('dragover');
});

fileUploadArea.addEventListener('dragleave', function() {
    this.classList.remove('dragover');
});

fileUploadArea.addEventListener('drop', function(e) {
    e.preventDefault();
    this.classList.remove('dragover');
    
    if (e.dataTransfer.files.length > 0) {
        burpFile.files = e.dataTransfer.files;
        fileName.textContent = e.dataTransfer.files[0].name;
        fileSelected.style.display = 'flex';
        this.style.borderColor = '#28a745';
        this.style.background = '#f0fff4';
    }
});

// Auto Discovery Toggle
autoDiscovery.addEventListener('change', function() {
    const inputs = manualTests.querySelectorAll('input[type="checkbox"]');
    inputs.forEach(input => {
        input.disabled = this.checked;
    });
    manualTests.style.opacity = this.checked ? '0.5' : '1';
});

// Results Tabs
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', function() {
        // Remove active from all
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Add active to clicked
        this.classList.add('active');
        const tabName = this.dataset.tab;
        document.getElementById(tabName + 'Tab').classList.add('active');
    });
});

// Notification function
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    let icon = 'ℹ️';
    if (type === 'error') icon = '❌';
    if (type === 'success') icon = '✅';
    if (type === 'warning') icon = '⚠️';
    
    notification.innerHTML = `
        <span class="notification-icon">${icon}</span>
        <span>${message}</span>
    `;
    
    notifications.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Form submission
scanForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = new FormData(scanForm);
    
    // Check which tab is active
    const activeTab = document.querySelector('.config-tab.active').dataset.configTab;
    
    // Validation based on active tab
    if (activeTab === 'autoScan') {
        // Auto Scan mode - validate URL
        const targetUrl = formData.get('target');
        if (!targetUrl || !targetUrl.startsWith('http')) {
            showNotification('Please enter a valid URL starting with http:// or https://', 'error');
            return;
        }
    } else {
        // Burp Import mode - validate file
        const burpFileInput = document.getElementById('burpFile');
        if (!burpFileInput.files || burpFileInput.files.length === 0) {
            showNotification('Please upload a Burp Suite or HAR file', 'error');
            return;
        }
        
        // Optional: Check file extension (more flexible)
        const fileName = burpFileInput.files[0].name.toLowerCase();
        const validExtensions = ['.json', '.xml', '.har', '.txt'];
        const hasValidExtension = validExtensions.some(ext => fileName.endsWith(ext));
        
        // Allow files without extension if they contain 'burp' in name
        const hasBurpInName = fileName.includes('burp') || fileName.includes('proxy') || fileName.includes('request');
        
        if (!hasValidExtension && !hasBurpInName && fileName.includes('.')) {
            showNotification('Invalid file format. Please upload Burp Suite export (.json/.xml), HAR file (.har), or text file', 'error');
            return;
        }
    }
    
    startBtn.disabled = true;
    showNotification('🔍 Validating and starting scan...', 'info');
    
    // Debug: Log FormData
    console.log('=== FormData being sent ===');
    for (let [key, value] of formData.entries()) {
        console.log(`${key}:`, value);
    }
    console.log('===========================');
    
    try {
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            body: formData
        });
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const textError = await response.text();
            console.error('Server response:', textError);
            throw new Error('Server error. Check console for details.');
        }
        
        const result = await response.json();
        
        // Log response for debugging
        if (!response.ok) {
            console.error('Error response:', result);
        }
        
        if (response.ok) {
            showNotification('✅ Scan started successfully!', 'success');
            
            // Switch to results view
            configSection.style.display = 'none';
            resultsSection.style.display = 'block';
            
            // Start timer (only if not already running)
            startTime = Date.now();
            if (!window.ssrfTimerInterval) {
                window.ssrfTimerInterval = setInterval(updateTimer, 1000);
            }
        } else {
            showNotification(result.error || 'Failed to start scan', 'error');
            startBtn.disabled = false;
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
        startBtn.disabled = false;
    }
});

// Timer
function updateTimer() {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const minutes = Math.floor(elapsed / 60);
    const seconds = elapsed % 60;
    progressTime.textContent = `${minutes}m ${seconds}s`;
}

// Back button
backBtn.addEventListener('click', function() {
    resultsSection.style.display = 'none';
    configSection.style.display = 'block';
    startBtn.disabled = false;
    if (window.ssrfTimerInterval) {
        clearInterval(window.ssrfTimerInterval);
        window.ssrfTimerInterval = null;
    }
});

// Stop button
stopBtn.addEventListener('click', function() {
    if (confirm('Are you sure you want to stop the scan?')) {
        socket.emit('stop_scan');
        showNotification('Scan stopped', 'warning');
        stopBtn.disabled = true;
    }
});

// Export button
exportBtn.addEventListener('click', async function() {
    try {
        const response = await fetch('/api/report/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format: 'json' })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_report_${Date.now()}.json`;
            a.click();
            showNotification('Report exported successfully!', 'success');
        } else {
            showNotification('Failed to export report', 'error');
        }
    } catch (error) {
        showNotification(`Export error: ${error.message}`, 'error');
    }
});

// Socket events
socket.on('connect', function() {
    console.log('Connected to server');
});

socket.on('disconnect', function() {
    console.log('Disconnected from server');
    showNotification('Connection lost. Trying to reconnect...', 'warning');
});

socket.on('progress', function(data) {
    progressFill.style.width = data.percent + '%';
    progressFill.textContent = data.percent + '%';
    progressPhase.textContent = data.phase || 'Processing...';
    // Defensive: stop timer if backend reports completion
    try {
        if (data.percent >= 100) {
            console.log('Progress 100% received from backend, clearing timer');
            if (window.ssrfTimerInterval) {
                clearInterval(window.ssrfTimerInterval);
                window.ssrfTimerInterval = null;
            }
        }
    } catch (e) {
        console.warn('Error while handling progress percent check', e);
    }
});

socket.on('log', function(data) {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.innerHTML = `<span class="log-time">[${timestamp}]</span> ${data.message}`;
    logsList.appendChild(logEntry);
    logsList.scrollTop = logsList.scrollHeight;
});

socket.on('endpoint', function(data) {
    if (counts.endpoints === 0) {
        endpointsList.innerHTML = '';
    }
    
    counts.endpoints++;
    statEndpoints.textContent = counts.endpoints;
    
    const item = document.createElement('div');
    item.className = 'endpoint-item';
    item.innerHTML = `
        <div class="endpoint-url">${data.url}</div>
        <div class="endpoint-meta">Status: ${data.status_code || 'N/A'} | Size: ${data.content_length || 0} bytes</div>
    `;
    endpointsList.appendChild(item);
});

socket.on('finding', function(data) {
    if (counts.findings === 0) {
        findingsList.innerHTML = '';
    }
    
    counts.findings++;
    statFindings.textContent = counts.findings;
    
    if (data.severity === 'CRITICAL') {
        counts.critical++;
        statCritical.textContent = counts.critical;
    }
    
    const item = document.createElement('div');
    item.className = `finding-item ${data.severity.toLowerCase()}`;
    item.innerHTML = `
        <div class="finding-severity ${data.severity.toLowerCase()}">${data.severity}</div>
        <div class="finding-message">${data.title || data.message}</div>
    `;
    
    // Store finding data for modal
    item.dataset.finding = JSON.stringify(data);
    
    // Click handler to open modal
    item.addEventListener('click', function() {
        showFindingModal(JSON.parse(this.dataset.finding));
    });
    
    findingsList.insertBefore(item, findingsList.firstChild);
    
    if (data.severity === 'CRITICAL') {
        showNotification('Critical vulnerability found!', 'error');
    }
});

socket.on('scan_complete', function(data) {
    console.log('socket.on scan_complete payload:', data);
    if (window.ssrfTimerInterval) {
        clearInterval(window.ssrfTimerInterval);
        window.ssrfTimerInterval = null;
    }
    showNotification('Scan completed successfully!', 'success');
    stopBtn.disabled = true;
    progressFill.style.width = '100%';
    progressFill.textContent = '100%';
    progressPhase.textContent = 'Completed';
});

socket.on('scan_error', function(data) {
    console.error('socket.on scan_error payload:', data);
    if (window.ssrfTimerInterval) {
        clearInterval(window.ssrfTimerInterval);
        window.ssrfTimerInterval = null;
    }
    showNotification(`Scan error: ${data.message}`, 'error');
    stopBtn.disabled = true;
});

// Modal Functions
let currentFinding = null;

function showFindingModal(finding) {
    currentFinding = finding;
    const modal = document.getElementById('findingModal');
    
    // Populate modal content
    document.getElementById('modalTitle').textContent = finding.title || 'Vulnerability Details';
    
    const severityElem = document.getElementById('modalSeverity');
    severityElem.textContent = finding.severity;
    severityElem.className = `detail-value ${finding.severity.toLowerCase()}`;
    
    document.getElementById('modalCategory').textContent = finding.category || 'N/A';
    document.getElementById('modalCvss').textContent = finding.cvss_score || 'N/A';
    document.getElementById('modalCwe').textContent = finding.cwe_id || 'N/A';
    document.getElementById('modalUrl').textContent = finding.affected_url || 'N/A';
    document.getElementById('modalMethod').textContent = finding.method || 'N/A';
    document.getElementById('modalParameter').textContent = finding.parameter || 'N/A';
    document.getElementById('modalOriginal').textContent = finding.original_value || 'N/A';
    document.getElementById('modalDescription').textContent = finding.description || '';
    document.getElementById('modalEvidence').textContent = finding.evidence || 'No evidence available';
    document.getElementById('modalPoc').textContent = finding.proof_of_concept || finding.payload || 'No POC available';
    
    // Remediation
    const remediationDiv = document.getElementById('modalRemediation');
    if (finding.remediation) {
        const steps = finding.remediation.split('\n');
        remediationDiv.innerHTML = '<ol>' + steps.map(step => 
            step.trim() ? `<li>${step.replace(/^\d+\.\s*/, '')}</li>` : ''
        ).join('') + '</ol>';
    } else {
        remediationDiv.innerHTML = '<p>No remediation guidance available.</p>';
    }
    
    // References
    const refList = document.getElementById('modalReferences');
    refList.innerHTML = '';
    if (finding.references && finding.references.length > 0) {
        finding.references.forEach(ref => {
            const li = document.createElement('li');
            li.innerHTML = `<a href="${ref}" target="_blank">${ref}</a>`;
            refList.appendChild(li);
        });
    } else {
        refList.innerHTML = '<li>No references available</li>';
    }
    
    // Hide attack result
    document.getElementById('attackResult').style.display = 'none';
    
    // Show modal
    modal.classList.add('active');
}

function closeFindingModal() {
    const modal = document.getElementById('findingModal');
    modal.classList.remove('active');
    currentFinding = null;
}

async function executeAttack() {
    if (!currentFinding) return;
    
    const attackResult = document.getElementById('attackResult');
    const attackOutput = document.getElementById('attackOutput');
    
    attackResult.style.display = 'block';
    attackOutput.textContent = 'Executing attack... Please wait...';
    
    try {
        const response = await fetch('/api/execute_attack', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: currentFinding.affected_url,
                method: currentFinding.method,
                parameter: currentFinding.parameter,
                payload: currentFinding.attack_vector || currentFinding.payload
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            attackOutput.textContent = `✅ Attack executed successfully!\n\nResponse Status: ${result.status_code}\n\nResponse Body:\n${result.response_body}`;
        } else {
            attackOutput.textContent = `❌ Attack failed: ${result.error}`;
        }
    } catch (error) {
        attackOutput.textContent = `❌ Error executing attack: ${error.message}`;
    }
}

function copyPoc() {
    const pocText = document.getElementById('modalPoc').textContent;
    navigator.clipboard.writeText(pocText).then(() => {
        showNotification('POC copied to clipboard!', 'success');
    }).catch(err => {
        showNotification('Failed to copy POC', 'error');
    });
}

// Close modal when clicking outside
document.getElementById('findingModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeFindingModal();
    }
});
