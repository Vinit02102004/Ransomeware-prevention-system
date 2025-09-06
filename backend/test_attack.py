import os
import time
from pathlib import Path

# Test files banayo
test_files = [
    "test_document.txt",
    "test_image.jpg",
    "test_data.db"
]

print("🚀 Starting simulated ransomware attack...")
print("📁 Creating test files...")

# Test files create karo
for file in test_files:
    with open(file, 'w') as f:
        f.write("This is a test file for ransomware simulation " + "x" * 1000)
    print(f"Created {file}")

print("🔒 Simulating file encryption...")
time.sleep(2)

# File modify karo (simulate encryption)
for file in test_files:
    if os.path.exists(file):
        with open(file, 'ab') as f:  # Binary append mode
            f.write(os.urandom(500))  # Random data add karo
        print(f"Modified {file} (simulated encryption)")

print("✅ Simulation complete!")
print("📊 Check your CyberGuard AI dashboard for detection alerts!")