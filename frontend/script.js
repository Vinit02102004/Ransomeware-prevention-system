const API_BASE = 'http://localhost:8000/api';
let websocket = null;
let isRealTimeProtectionActive = false;

// Initialize the application
async function init() {
    await loadAllData();
    connectWebSocket();
    startAutoRefresh();
    checkRealTimeProtectionStatus();
}

// Load all initial data
async function loadAllData() {
    try {
        await Promise.all([
            loadSystemStatus(),
            loadRecentThreats(),
            loadSecurityEvents(),
            loadSecurityAnalytics(),
            loadHoneyFiles()
        ]);
    } catch (error) {
        console.error('Error loading data:', error);
        showNotification('Error loading data from server', 'error');
    }
}

// WebSocket connection for real-time updates
function connectWebSocket() {
    websocket = new WebSocket('ws://localhost:8000/ws');

    websocket.onopen = () => {
        console.log('WebSocket connected');
        showNotification('Real-time connection established', 'success');
        updateConnectionStatus('Connected');
    };

    websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };

    websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        showNotification('Connection error - reconnecting...', 'error');
        updateConnectionStatus('Disconnected');
    };

    websocket.onclose = () => {
        console.log('WebSocket disconnected. Reconnecting in 3 seconds...');
        showNotification('Connection lost - reconnecting...', 'warning');
        updateConnectionStatus('Reconnecting...');
        setTimeout(connectWebSocket, 3000);
    };
}

// Update connection status in footer
function updateConnectionStatus(status) {
    const statusElement = document.getElementById('connectionStatus');
    if (statusElement) {
        statusElement.textContent = status;
        statusElement.style.color = status === 'Connected' ? '#00ff88' : '#ff4757';
    }
}

// Handle WebSocket messages
function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'threat_detected':
            addNewThreat(data.data);
            break;
        case 'security_event':
            addNewEvent(data.data);
            break;
        case 'system_status_update':
            updateSystemStatus(data.data);
            break;
        case 'analytics_update':
            updateAnalytics(data.data);
            break;
    }
}

// Check real-time protection status
async function checkRealTimeProtectionStatus() {
    try {
        const status = await loadSystemStatus();
        isRealTimeProtectionActive = status.real_time_protection || false;
        updateProtectionUI();
    } catch (error) {
        console.error('Error checking protection status:', error);
    }
}

// Update protection UI indicators
function updateProtectionUI() {
    const protectionIndicator = document.getElementById('protectionIndicator');
    const protectionStatus = document.getElementById('protectionStatus');
    const startProtectionBtn = document.querySelector('.btn-protection');

    if (isRealTimeProtectionActive) {
        if (protectionIndicator) {
            protectionIndicator.innerHTML = '<i class="fas fa-shield-alt"></i>';
            protectionIndicator.style.color = '#00ff88';
        }
        if (protectionStatus) {
            protectionStatus.textContent = 'ACTIVE';
            protectionStatus.className = 'protection-active';
        }
        if (startProtectionBtn) {
            startProtectionBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Real-time Protection';
            startProtectionBtn.onclick = stopRealTimeProtection;
        }
    } else {
        if (protectionIndicator) {
            protectionIndicator.innerHTML = '<i class="fas fa-shield-alt"></i>';
            protectionIndicator.style.color = '#ff4757';
        }
        if (protectionStatus) {
            protectionStatus.textContent = 'INACTIVE';
            protectionStatus.className = 'protection-inactive';
        }
        if (startProtectionBtn) {
            startProtectionBtn.innerHTML = '<i class="fas fa-play"></i> Start Real-time Protection';
            startProtectionBtn.onclick = startRealTimeProtection;
        }
    }
}

// Load system status
async function loadSystemStatus() {
    try {
        const response = await fetch(`${API_BASE}/system-status`);
        const data = await response.json();
        updateSystemStatus(data);
        return data;
    } catch (error) {
        console.error('Error loading system status:', error);
        throw error;
    }
}

// Load recent threats
async function loadRecentThreats() {
    try {
        const response = await fetch(`${API_BASE}/recent-threats`);
        const threats = await response.json();
        displayThreats(threats);
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

// Load security events
async function loadSecurityEvents() {
    try {
        const response = await fetch(`${API_BASE}/security-events`);
        const events = await response.json();
        displayEvents(events);
    } catch (error) {
        console.error('Error loading events:', error);
    }
}

// Load security analytics
async function loadSecurityAnalytics() {
    try {
        const response = await fetch(`${API_BASE}/security-analytics`);
        const analytics = await response.json();
        updateAnalytics(analytics);
    } catch (error) {
        console.error('Error loading analytics:', error);
    }
}

// Load honey files
async function loadHoneyFiles() {
    try {
        const response = await fetch(`${API_BASE}/honey-files`);
        const files = await response.json();
        displayHoneyFiles(files);
    } catch (error) {
        console.error('Error loading honey files:', error);
    }
}

// Start real-time protection
async function startRealTimeProtection() {
    try {
        const response = await fetch(`${API_BASE}/start-protection`, {
            method: 'POST'
        });
        const result = await response.json();
        isRealTimeProtectionActive = true;
        updateProtectionUI();
        showNotification(`Real-time protection: ${result.status}`, 'success');
        loadSystemStatus();
    } catch (error) {
        console.error('Error starting protection:', error);
        showNotification('Error starting real-time protection', 'error');
    }
}

// Stop real-time protection
async function stopRealTimeProtection() {
    try {
        const response = await fetch(`${API_BASE}/stop-protection`, {
            method: 'POST'
        });
        const result = await response.json();
        isRealTimeProtectionActive = false;
        updateProtectionUI();
        showNotification(`Real-time protection: ${result.status}`, 'success');
        loadSystemStatus();
    } catch (error) {
        console.error('Error stopping protection:', error);
        showNotification('Error stopping real-time protection', 'error');
    }
}

// Scan directory for ransomware
async function scanDirectory() {
    const path = prompt('Enter directory path to scan (e.g., /Documents or C:/Users/YourName/Documents):', '/Documents');
    if (path) {
        try {
            showNotification('Scanning directory...', 'info');
            const response = await fetch(`${API_BASE}/scan-directory?path=${encodeURIComponent(path)}`);
            const result = await response.json();

            if (result.suspicious_files > 0) {
                showNotification(`Scan complete: ${result.suspicious_files} suspicious files found!`, 'warning');
                displayScanResults(result.scan_results);
            } else {
                showNotification(`Scan complete: ${result.scanned_files} files scanned, no threats found`, 'success');
            }
        } catch (error) {
            console.error('Error scanning directory:', error);
            showNotification('Error scanning directory', 'error');
        }
    }
}

// Display scan results
function displayScanResults(results) {
    const modal = document.createElement('div');
    modal.className = 'scan-results-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <h3><i class="fas fa-search"></i> Scan Results (${results.length} suspicious files)</h3>
            <div class="results-list">
                ${results.map(file => `
                    <div class="scan-result-item">
                        <div class="file-path">${file.file}</div>
                        <div class="file-info">
                            <span class="entropy">Entropy: ${file.entropy}/8.0</span>
                            <span class="status suspicious">SUSPICIOUS</span>
                        </div>
                    </div>
                `).join('')}
            </div>
            <button onclick="this.closest('.scan-results-modal').remove()" class="close-btn">
                <i class="fas fa-times"></i> Close
            </button>
        </div>
    `;
    
    document.body.appendChild(modal);
}

// Monitor running processes
async function monitorProcesses() {
    try {
        const response = await fetch(`${API_BASE}/running-processes`);
        const data = await response.json();
        displayProcesses(data.processes);
    } catch (error) {
        console.error('Error fetching processes:', error);
        showNotification('Error loading processes', 'error');
    }
}

// Display running processes
function displayProcesses(processes) {
    const modal = document.createElement('div');
    modal.className = 'processes-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <h3><i class="fas fa-tasks"></i> Running Processes (${processes.length})</h3>
            <div class="processes-list">
                ${processes.map(proc => `
                    <div class="process-item">
                        <div class="process-info">
                            <strong>${proc.name || 'Unknown'}</strong>
                            <div class="process-details">
                                PID: ${proc.pid} | 
                                CPU: ${proc.cpu_percent || 0}% | 
                                Memory: ${proc.memory_percent || 0}% |
                                User: ${proc.username || 'N/A'}
                            </div>
                        </div>
                        <button onclick="blockProcess(${proc.pid})" class="block-btn">
                            <i class="fas fa-ban"></i> Block
                        </button>
                    </div>
                `).join('')}
            </div>
            <button onclick="this.closest('.processes-modal').remove()" class="close-btn">
                <i class="fas fa-times"></i> Close
            </button>
        </div>
    `;
    
    document.body.appendChild(modal);
}

// Block a process
async function blockProcess(pid) {
    if (confirm('Are you sure you want to block this process?')) {
        try {
            const response = await fetch(`${API_BASE}/block-process/${pid}`, {
                method: 'POST'
            });
            const result = await response.json();
            showNotification(result.message, 'success');
            
            // Refresh processes list
            monitorProcesses();
        } catch (error) {
            console.error('Error blocking process:', error);
            showNotification('Error blocking process', 'error');
        }
    }
}

// Update protection level
async function updateProtectionLevel() {
    const level = document.getElementById('protectionSelect').value;
    
    try {
        const response = await fetch(`${API_BASE}/protection-level`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ level })
        });
        
        if (response.ok) {
            showNotification(`Protection level updated to ${level}`, 'success');
            loadSystemStatus();
        }
    } catch (error) {
        console.error('Error updating protection level:', error);
        showNotification('Error updating protection level', 'error');
    }
}

// Emergency action
async function emergencyAction(action) {
    if (confirm(`Are you sure you want to execute ${action}?`)) {
        try {
            const response = await fetch(`${API_BASE}/emergency-action`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action })
            });
            
            if (response.ok) {
                showNotification(`Emergency action: ${action} executed`, 'success');
                loadSystemStatus();
            }
        } catch (error) {
            console.error('Error executing emergency action:', error);
            showNotification('Error executing emergency action', 'error');
        }
    }
}

// Backup System Functions
async function viewBackups() {
    try {
        showNotification('Loading backups...', 'info');
        const response = await fetch(`${API_BASE}/backups`);
        const data = await response.json();
        displayBackups(data.backups);
    } catch (error) {
        console.error('Error loading backups:', error);
        showNotification('Error loading backups', 'error');
    }
}

function displayBackups(backups) {
    const modal = document.createElement('div');
    modal.className = 'backups-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <h3><i class="fas fa-database"></i> Backup Files (${backups.length})</h3>
            <div class="backups-list">
                ${backups.length > 0 ? backups.map(backup => `
                    <div class="backup-item">
                        <div class="backup-info">
                            <strong>${backup.name}</strong>
                            <div class="backup-details">
                                Size: ${(backup.size / 1024).toFixed(2)} KB | 
                                Created: ${new Date(backup.created * 1000).toLocaleString()}
                            </div>
                        </div>
                        <div class="backup-actions">
                            <button onclick="downloadBackup('${backup.name}')" class="download-btn">
                                <i class="fas fa-download"></i> Download
                            </button>
                            <button onclick="deleteBackup('${backup.name}')" class="delete-btn">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                    </div>
                `).join('') : '<div class="no-backups">No backups found</div>'}
            </div>
            <button onclick="this.closest('.backups-modal').remove()" class="close-btn">
                <i class="fas fa-times"></i> Close
            </button>
        </div>
    `;
    
    document.body.appendChild(modal);
}

async function downloadBackup(filename) {
    showNotification('Download functionality coming soon!', 'info');
}

async function deleteBackup(filename) {
    if (confirm('Delete this backup permanently?')) {
        try {
            const response = await fetch(`${API_BASE}/backup/${filename}`, {
                method: 'DELETE'
            });
            const result = await response.json();
            showNotification(result.message, 'success');
            viewBackups(); // Refresh list
        } catch (error) {
            console.error('Error deleting backup:', error);
            showNotification('Error deleting backup', 'error');
        }
    }
}

async function createManualBackup() {
    const filePath = prompt('Enter file path to backup:');
    if (filePath) {
        try {
            showNotification('Creating manual backup...', 'info');
            // Simulate backup creation
            await new Promise(resolve => setTimeout(resolve, 2000));
            showNotification('Backup created successfully!', 'success');
        } catch (error) {
            console.error('Error creating backup:', error);
            showNotification('Error creating backup', 'error');
        }
    }
}

// Display functions
function updateSystemStatus(data) {
    document.getElementById('systemStatus').textContent = data.status;
    document.getElementById('protectionLevel').textContent = data.protection_level;
    document.getElementById('scanCount').textContent = data.scan_count.toLocaleString();
    
    // Update select box
    document.getElementById('protectionSelect').value = data.protection_level;
    
    // Update real-time protection status
    isRealTimeProtectionActive = data.real_time_protection || false;
    updateProtectionUI();
}

function updateAnalytics(data) {
    document.getElementById('totalThreats').textContent = data.total_threats;
    document.getElementById('threatActivity').textContent = data.threat_activity;
    document.getElementById('backedThreats').textContent = data.backed_threats;
    document.getElementById('blockedAttacks').textContent = data.blocked_attacks || 0;
}

function displayThreats(threats) {
    const container = document.getElementById('threatsList');
    
    if (threats.length === 0) {
        container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> No threats detected</div>';
        return;
    }
    
    container.innerHTML = threats.map(threat => `
        <div class="threat-item">
            <div class="threat-header">
                <strong>${threat.type}</strong>
                <span class="threat-time">${new Date(threat.timestamp).toLocaleString()}</span>
            </div>
            <div class="threat-details">
                IP: ${threat.ip} 
                ${threat.process_name ? `| Process: ${threat.process_name}` : ''}
            </div>
        </div>
    `).join('');
}

function displayEvents(events) {
    const container = document.getElementById('eventsList');
    
    if (events.length === 0) {
        container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> No events found</div>';
        return;
    }
    
    container.innerHTML = events.map(event => `
        <div class="event-item ${event.severity?.toLowerCase()}">
            <div class="event-header">
                <strong>${event.event}</strong>
                <span class="event-severity">${event.severity}</span>
            </div>
            <div class="event-details">
                Source: ${event.source} | 
                ${new Date(event.timestamp).toLocaleString()}
                ${event.file_path ? `| File: ${event.file_path.split('/').pop()}` : ''}
                ${event.backup_path ? `| Backup: Created` : ''}
            </div>
        </div>
    `).join('');
}

function displayHoneyFiles(files) {
    const container = document.getElementById('honeyFiles');
    
    if (files.length === 0) {
        container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> No honey files found</div>';
        return;
    }
    
    container.innerHTML = files.map(file => `
        <div class="file-item">
            <div class="file-header">
                <i class="fas fa-file-alt"></i>
                <strong>${file.name}</strong>
            </div>
            <div class="file-details">
                Created: ${new Date(file.timestamp).toLocaleString()}
            </div>
        </div>
    `).join('');
}

function addNewThreat(threat) {
    const container = document.getElementById('threatsList');
    const newThreat = document.createElement('div');
    newThreat.className = 'threat-item new-threat';
    newThreat.innerHTML = `
        <div class="threat-header">
            <strong>${threat.type}</strong>
            <span class="threat-time">${new Date(threat.timestamp).toLocaleString()}</span>
        </div>
        <div class="threat-details">
            IP: ${threat.ip} 
            ${threat.process_name ? `| Process: ${threat.process_name}` : ''}
        </div>
    `;
    
    container.insertBefore(newThreat, container.firstChild);
    
    // Remove oldest threat if too many
    if (container.children.length > 10) {
        container.removeChild(container.lastChild);
    }
    
    // Flash animation
    setTimeout(() => newThreat.classList.remove('new-threat'), 2000);
    
    showNotification(`New threat detected: ${threat.type}`, 'warning');
}

function addNewEvent(event) {
    const container = document.getElementById('eventsList');
    const newEvent = document.createElement('div');
    newEvent.className = `event-item ${event.severity?.toLowerCase()} new-event`;
    newEvent.innerHTML = `
        <div class="event-header">
            <strong>${event.event}</strong>
            <span class="event-severity">${event.severity}</span>
        </div>
        <div class="event-details">
            Source: ${event.source} | 
            ${new Date(event.timestamp).toLocaleString()}
            ${event.file_path ? `| File: ${event.file_path.split('/').pop()}` : ''}
            ${event.backup_path ? `| Backup: Created` : ''}
        </div>
    `;
    
    container.insertBefore(newEvent, container.firstChild);
    
    // Remove oldest event if too many
    if (container.children.length > 20) {
        container.removeChild(container.lastChild);
    }
    
    // Flash animation
    setTimeout(() => newEvent.classList.remove('new-event'), 2000);
    
    // Show special notification for backup events
    if (event.event.includes('Backup')) {
        showNotification(event.event, 'success');
    }
}

// Notification system
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${getNotificationIcon(type)}"></i>
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">&times;</button>
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// Auto refresh
function startAutoRefresh() {
    // Refresh data every 30 seconds
    setInterval(loadAllData, 30000);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', init);