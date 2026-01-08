import subprocess
import sys

print("Running lab-multi...")
result = subprocess.run([sys.executable, "lab-multi.py"])

if result.returncode != 0:
    print("lab-multi failed. Stopping execution.")
    sys.exit(result.returncode)

print("Running lab-single...")
subprocess.run([sys.executable, "lab-single.py"])
