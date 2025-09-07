from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import asyncio
import random
import os
import psutil
import math
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
from typing import List, Dict
from bson import ObjectId
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from models import (
    Threat, SecurityEvent, SystemStatus, 
    SecurityAnalytics, HoneyFile, ProtectionLevelUpdate, EmergencyAction
)
from database import connect_to_mongo, close_mongo_connection, mongodb
from config import settings

app = FastAPI(title="Ransomware Prevention System API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connections
active_connections: List[WebSocket] = []

# Email configuration
class EmailConfig:
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = "vinitgandhi15@gmail.com"
    SENDER_PASSWORD = "bvrc gicr feyz mpms"
    RECEIVER_EMAIL = "vinitgandhi15@gmail.com"
    ENABLED = True

# Email service
class EmailService:
    @staticmethod
    async def send_email_alert(threat_data: dict, event_type: str = "THREAT"):
        if not EmailConfig.ENABLED:
            return False
            
        try:
            msg = MIMEMultipart()
            msg['From'] = EmailConfig.SENDER_EMAIL
            msg['To'] = EmailConfig.RECEIVER_EMAIL
            
            if event_type == "THREAT":
                msg['Subject'] = f"🚨 Ransomware Threat Detected - {threat_data.get('type', 'Unknown')}"
                body = f"""
⚠️ CYBERGUARD ALERT - RANSOMWARE THREAT DETECTED ⚠️

🔍 Threat Details:
• Type: {threat_data.get('type', 'Unknown')}
• Source IP: {threat_data.get('ip', 'Unknown')}
• Timestamp: {threat_data.get('timestamp', 'Unknown')}
• Severity: {threat_data.get('severity', 'MEDIUM')}

🛡️ System Response:
• Protection Level: {threat_data.get('protection_level', 'HIGH')}
• Status: {threat_data.get('status', 'SECURE')}
• Blocked: {threat_data.get('blocked', 'Yes')}

📊 Additional Info:
• Total Threats: {threat_data.get('total_threats', 0)}
• Blocked Attacks: {threat_data.get('blocked_attacks', 0)}

🔗 Dashboard: http://localhost:8080

Stay vigilant!
CyberGuard AI System
"""
            else:
                msg['Subject'] = f"🔔 Security Event - {threat_data.get('event', 'Unknown')}"
                body = f"""
📋 SECURITY EVENT NOTIFICATION

🔍 Event Details:
• Event: {threat_data.get('event', 'Unknown')}
• Source: {threat_data.get('source', 'Unknown')}
• Timestamp: {threat_data.get('timestamp', 'Unknown')}
• Severity: {threat_data.get('severity', 'INFO')}

📊 System Status:
• Protection Level: {threat_data.get('protection_level', 'HIGH')}
• Status: {threat_data.get('status', 'SECURE')}

🔗 Dashboard: http://localhost:8080

CyberGuard AI Monitoring
"""

            msg.attach(MIMEText(body, 'plain'))
            context = ssl.create_default_context()

            with smtplib.SMTP(EmailConfig.SMTP_SERVER, EmailConfig.SMTP_PORT) as server:
                server.starttls(context=context)
                server.login(EmailConfig.SENDER_EMAIL, EmailConfig.SENDER_PASSWORD)
                server.send_message(msg)

            print(f"✅ Email alert sent for {event_type}")
            return True

        except Exception as e:
            print(f"❌ Email sending failed: {e}")
            return False

# Ransomware detector
class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        self.suspicious_processes = set()
        self.protected_directories = ["/Documents", "/Desktop", "/Downloads", "/Pictures"]
        self.observer = None
        
    def on_modified(self, event):
        if not event.is_directory:
            asyncio.create_task(self.handle_file_event(event.src_path))
    
    async def handle_file_event(self, file_path):
        backup_created = await create_backup(file_path)
        self.check_file_encryption(file_path)
        
    def check_file_encryption(self, file_path):
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                if any(x in file_path for x in ['.tmp', '.temp', '~$']):
                    return
                    
                with open(file_path, 'rb') as f:
                    data = f.read()
                    if len(data) > 1024:
                        entropy = self.calculate_entropy(data)
                        if entropy > 7.8:
                            asyncio.create_task(self.block_ransomware(file_path))
                            
        except Exception as e:
            print(f"Error checking file {file_path}: {e}")
    
    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    
    async def block_ransomware(self, file_path):
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if any(file_path in str(f.path) for f in proc.info['open_files'] or []):
                        proc.terminate()
                        await self.log_ransomware_block(proc.info['name'], file_path, proc.info['pid'])
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print(f"Error blocking ransomware: {e}")
    
    async def log_ransomware_block(self, process_name, file_path, pid):
        event = {
            "event": f"Ransomware blocked: {process_name} (PID: {pid})",
            "source": "SYSTEM",
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "file_path": file_path,
            "action": "process_terminated"
        }
        
        await mongodb.database.security_events.insert_one(event)
        await broadcast_update(event, "security_event")
        
        threat = {
            "type": "Ransomware Blocked",
            "ip": "127.0.0.1",
            "timestamp": datetime.now(),
            "process_name": process_name,
            "file_path": file_path
        }
        await mongodb.database.threats.insert_one(threat)
        await broadcast_update(threat, "threat_detected")
        
        # Send email alert
        email_data = {
            "event": f"Ransomware blocked: {process_name}",
            "source": "SYSTEM",
            "timestamp": datetime.now().isoformat(),
            "severity": "CRITICAL",
            "protection_level": "HIGH",
            "status": "SECURE"
        }
        await EmailService.send_email_alert(email_data, "EVENT")

    def start_monitoring(self):
        if self.observer and self.observer.is_alive():
            return False
            
        self.observer = Observer()
        monitored_paths = []
        
        for directory in self.protected_directories:
            path = str(Path.home() / directory[1:])
            if os.path.exists(path):
                self.observer.schedule(self, path, recursive=True)
                monitored_paths.append(path)
        
        if monitored_paths:
            self.observer.start()
            return True
        return False
        
    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            return True
        return False

# Initialize detector
ransomware_detector = RansomwareDetector()

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    await connect_to_mongo()
    await initialize_default_data()
    asyncio.create_task(simulate_threat_detection())
    asyncio.create_task(simulate_system_scan())

@app.on_event("shutdown")
async def shutdown_event():
    ransomware_detector.stop_monitoring()
    await close_mongo_connection()

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def broadcast_update(data: Dict, update_type: str):
    def datetime_converter(o):
        if isinstance(o, datetime):
            return o.isoformat()
        return o
    
    try:
        message = {"type": update_type, "data": data}
        json_message = json.dumps(message, default=datetime_converter)
        for connection in active_connections:
            try:
                await connection.send_text(json_message)
            except Exception as e:
                print(f"Error sending message to WebSocket: {e}")
    except Exception as e:
        print(f"Error serializing message: {e}")

# Backup function
async def create_backup(file_path):
    try:
        if os.path.exists(file_path):
            backup_dir = Path.home() / "CyberGuardBackups"
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = Path(file_path).name
            backup_path = backup_dir / f"{filename}_{timestamp}.bak"
            
            shutil.copy2(file_path, backup_path)
            
            event = {
                "event": f"Backup created: {filename}",
                "source": "BACKUP_SYSTEM",
                "timestamp": datetime.now().isoformat(),
                "severity": "INFO",
                "backup_path": str(backup_path)
            }
            await mongodb.database.security_events.insert_one(event)
            await broadcast_update(event, "security_event")
            
            return True
    except Exception as e:
        print(f"Backup error: {e}")
    return False

async def initialize_default_data():
    status_count = await mongodb.database.system_status.count_documents({})
    if status_count == 0:
        default_status = {
            "status": "SECURE",
            "protection_level": "HIGH",
            "scan_count": 1247863,
            "real_time_protection": False
        }
        await mongodb.database.system_status.insert_one(default_status)
    
    analytics_count = await mongodb.database.security_analytics.count_documents({})
    if analytics_count == 0:
        default_analytics = {
            "total_threats": 202,
            "threat_activity": 241,
            "response_time": "0.5x",
            "backed_threats": 193,
            "blocked_attacks": 0
        }
        await mongodb.database.security_analytics.insert_one(default_analytics)
    
    honey_files_count = await mongodb.database.honey_files.count_documents({})
    if honey_files_count == 0:
        current_time = datetime.now()
        default_honey_files = [
            {"name": "customer_diskbase.sql", "timestamp": current_time},
            {"name": "employee_data.csv", "timestamp": current_time},
            {"name": "user_credentials.db", "timestamp": current_time}
        ]
        for file in default_honey_files:
            await mongodb.database.honey_files.insert_one(file)

# API endpoints
@app.get("/")
async def root():
    return {"message": "Ransomware Prevention System API"}

@app.get("/api/system-status", response_model=SystemStatus)
async def get_system_status():
    status = await mongodb.database.system_status.find_one()
    if status:
        status_data = {k: v for k, v in status.items() if k != '_id'}
        return status_data
    raise HTTPException(status_code=404, detail="System status not found")

@app.get("/api/recent-threats", response_model=List[Threat])
async def get_recent_threats(limit: int = 10):
    threats = await mongodb.database.threats.find().sort("timestamp", -1).limit(limit).to_list(limit)
    for threat in threats:
        threat.pop('_id', None)
    return threats

@app.get("/api/security-events", response_model=List[SecurityEvent])
async def get_security_events(limit: int = 20):
    events = await mongodb.database.security_events.find().sort("timestamp", -1).limit(limit).to_list(limit)
    for event in events:
        event.pop('_id', None)
    return events

@app.get("/api/security-analytics", response_model=SecurityAnalytics)
async def get_security_analytics():
    analytics = await mongodb.database.security_analytics.find_one()
    if analytics:
        analytics_data = {k: v for k, v in analytics.items() if k != '_id'}
        return analytics_data
    raise HTTPException(status_code=404, detail="Security analytics not found")

@app.get("/api/honey-files", response_model=List[HoneyFile])
async def get_honey_files():
    files = await mongodb.database.honey_files.find().sort("timestamp", -1).to_list(100)
    for file in files:
        file.pop('_id', None)
    return files

@app.post("/api/protection-level")
async def update_protection_level(update: ProtectionLevelUpdate):
    if update.level not in ["LOW", "MEDIUM", "HIGH"]:
        raise HTTPException(status_code=400, detail="Invalid protection level")
    
    await mongodb.database.system_status.update_one({}, {"$set": {"protection_level": update.level}})
    
    status = await mongodb.database.system_status.find_one()
    if status:
        status_data = {k: v for k, v in status.items() if k != '_id'}
        await broadcast_update(status_data, "system_status_update")
    
    return {"message": f"Protection level updated to {update.level}"}

@app.post("/api/emergency-action")
async def emergency_action(action: EmergencyAction):
    if action.action not in ["lockdown", "restart", "safe_mode"]:
        raise HTTPException(status_code=400, detail="Invalid emergency action")
    
    new_status = "LOCKDOWN" if action.action == "lockdown" else "SECURE"
    await mongodb.database.system_status.update_one({}, {"$set": {"status": new_status}})
    
    event = {
        "event": f"Emergency {action.action} activated",
        "source": "SYSTEM",
        "timestamp": datetime.now().isoformat(),
        "severity": "HIGH"
    }
    await mongodb.database.security_events.insert_one(event)
    
    status = await mongodb.database.system_status.find_one()
    if status:
        status_data = {k: v for k, v in status.items() if k != '_id'}
        await broadcast_update(status_data, "system_status_update")
    
    event.pop('_id', None)
    await broadcast_update(event, "security_event")
    
    # Send email alert for emergency action
    email_data = {
        "event": f"Emergency {action.action} activated",
        "source": "SYSTEM",
        "timestamp": datetime.now().isoformat(),
        "severity": "HIGH",
        "protection_level": "HIGH",
        "status": new_status
    }
    await EmailService.send_email_alert(email_data, "EVENT")
    
    return {"message": f"Emergency action {action.action} executed"}

# Ransomware protection endpoints
@app.post("/api/start-protection")
async def start_protection():
    try:
        success = ransomware_detector.start_monitoring()
        if success:
            await mongodb.database.system_status.update_one({}, {"$set": {"real_time_protection": True}})
            
            event = {
                "event": "Real-time protection started",
                "source": "SYSTEM",
                "timestamp": datetime.now().isoformat(),
                "severity": "INFO"
            }
            await mongodb.database.security_events.insert_one(event)
            await broadcast_update(event, "security_event")
            
            return {"message": "Real-time protection started", "status": "active"}
        else:
            raise HTTPException(status_code=500, detail="Failed to start monitoring")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stop-protection")
async def stop_protection():
    try:
        success = ransomware_detector.stop_monitoring()
        if success:
            await mongodb.database.system_status.update_one({}, {"$set": {"real_time_protection": False}})
            
            event = {
                "event": "Real-time protection stopped",
                "source": "SYSTEM",
                "timestamp": datetime.now().isoformat(),
                "severity": "INFO"
            }
            await mongodb.database.security_events.insert_one(event)
            await broadcast_update(event, "security_event")
            
            return {"message": "Real-time protection stopped", "status": "inactive"}
        else:
            raise HTTPException(status_code=500, detail="Failed to stop monitoring")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan-directory")
async def scan_directory(path: str = "/Documents"):
    try:
        full_path = str(Path.home() / path[1:]) if path.startswith("/") else path
        
        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail="Directory not found")
        
        results = []
        scanned_files = 0
        
        for root, _, files in os.walk(full_path):
            for file in files[:100]:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read(4096)
                        entropy = ransomware_detector.calculate_entropy(data)
                        if entropy > 7.8:
                            results.append({
                                "file": file_path,
                                "entropy": round(entropy, 2),
                                "status": "suspicious"
                            })
                    scanned_files += 1
                except Exception:
                    continue
        
        return {"scan_results": results, "scanned_files": scanned_files, "suspicious_files": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/running-processes")
async def get_running_processes():
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {"processes": processes[:50]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/block-process/{pid}")
async def block_process(pid: int):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        process.terminate()
        
        event = {
            "event": f"Process terminated: {process_name} (PID: {pid})",
            "source": "SYSTEM",
            "timestamp": datetime.now().isoformat(),
            "severity": "HIGH",
            "action": "process_terminated"
        }
        await mongodb.database.security_events.insert_one(event)
        await broadcast_update(event, "security_event")
        
        await mongodb.database.security_analytics.update_one({}, {"$inc": {"blocked_attacks": 1}})
        
        return {"message": f"Process {process_name} (PID: {pid}) terminated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Backup endpoints
@app.get("/api/backups")
async def get_backups():
    try:
        backup_dir = Path.home() / "CyberGuardBackups"
        backups = []
        
        if backup_dir.exists():
            for file in backup_dir.glob("*.bak"):
                backups.append({
                    "name": file.name,
                    "size": file.stat().st_size,
                    "created": file.stat().st_ctime,
                    "path": str(file)
                })
        return {"backups": sorted(backups, key=lambda x: x["created"], reverse=True)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/backup/{filename}")
async def delete_backup(filename: str):
    try:
        backup_dir = Path.home() / "CyberGuardBackups"
        file_path = backup_dir / filename
        
        if file_path.exists():
            file_path.unlink()
            return {"message": f"Backup {filename} deleted"}
        else:
            raise HTTPException(status_code=404, detail="Backup not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Email alert endpoints
@app.post("/api/email-alerts/enable")
async def enable_email_alerts():
    EmailConfig.ENABLED = True
    return {"message": "Email alerts enabled", "status": "enabled"}

@app.post("/api/email-alerts/disable")
async def disable_email_alerts():
    EmailConfig.ENABLED = False
    return {"message": "Email alerts disabled", "status": "disabled"}

@app.get("/api/email-alerts/status")
async def get_email_alerts_status():
    return {"enabled": EmailConfig.ENABLED}

@app.post("/api/email-alerts/test")
async def send_test_email():
    test_data = {
        "type": "Test Threat",
        "ip": "192.168.1.100",
        "timestamp": datetime.now().isoformat(),
        "severity": "TEST",
        "protection_level": "HIGH",
        "status": "SECURE",
        "blocked": "Yes",
        "total_threats": 999,
        "blocked_attacks": 999
    }
    success = await EmailService.send_email_alert(test_data, "THREAT")
    if success:
        return {"message": "Test email sent successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send test email")

# Background tasks
async def simulate_threat_detection():
    threat_types = ["Data Extracted", "File Encryption", "Data Extractor", "Ransomware Attempt"]
    ip_ranges = ["10.0.0.", "192.168.1.", "172.16.0."]
    
    while True:
        await asyncio.sleep(random.randint(5, 15))
        
        threat_type = random.choice(threat_types)
        ip_range = random.choice(ip_ranges)
        ip = ip_range + str(random.randint(1, 255))
        timestamp = datetime.now()
        
        threat = {"type": threat_type, "ip": ip, "timestamp": timestamp}
        await mongodb.database.threats.insert_one(threat)
        
        severities = ["LOW", "MEDIUM", "HIGH"]
        severity = random.choice(severities)
        
        event = {
            "event": f"{threat_type} attempt detected",
            "source": ip,
            "timestamp": timestamp,
            "severity": severity
        }
        await mongodb.database.security_events.insert_one(event)
        
        analytics = await mongodb.database.security_analytics.find_one()
        if analytics:
            new_total = analytics["total_threats"] + 1
            new_activity = analytics["threat_activity"] + random.randint(1, 5)
            
            await mongodb.database.security_analytics.update_one(
                {"_id": analytics["_id"]}, 
                {"$set": {"total_threats": new_total, "threat_activity": new_activity}}
            )
            
            updated_analytics = await mongodb.database.security_analytics.find_one()
            if updated_analytics:
                updated_analytics_data = {k: v for k, v in updated_analytics.items() if k != '_id'}
                await broadcast_update(updated_analytics_data, "analytics_update")
        
        # Send email alert for threat
        email_data = {
            "type": threat_type,
            "ip": ip,
            "timestamp": timestamp.isoformat(),
            "severity": severity,
            "protection_level": "HIGH",
            "status": "SECURE",
            "blocked": "Yes",
            "total_threats": new_total,
            "blocked_attacks": analytics.get("blocked_attacks", 0) if analytics else 0
        }
        await EmailService.send_email_alert(email_data, "THREAT")
        
        threat.pop('_id', None)
        event.pop('_id', None)
        
        await broadcast_update(threat, "threat_detected")
        await broadcast_update(event, "security_event")

async def simulate_system_scan():
    while True:
        await asyncio.sleep(30)
        
        status = await mongodb.database.system_status.find_one()
        if status:
            new_count = status["scan_count"] + random.randint(50, 100)
            await mongodb.database.system_status.update_one(
                {"_id": status["_id"]}, 
                {"$set": {"scan_count": new_count}}
            )
            
            updated_status = await mongodb.database.system_status.find_one()
            if updated_status:
                updated_status_data = {k: v for k, v in updated_status.items() if k != '_id'}
                await broadcast_update(updated_status_data, "system_status_update")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
