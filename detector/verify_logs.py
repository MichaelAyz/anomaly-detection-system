import subprocess

print("=== blocker.py ===")
subprocess.run(['grep', '-A4', 'audit_msg', '/home/ubuntu/hng-detector/detector/blocker.py'])

print("\n=== baseline.py ===")
subprocess.run(['grep', '-A4', 'audit_msg', '/home/ubuntu/hng-detector/detector/baseline.py'])

print("\n=== unbanner.py ===")
subprocess.run('grep -n "audit_msg\|UNBAN\|PERMANENT_BAN\|audit_log_path" /home/ubuntu/hng-detector/detector/unbanner.py', shell=True)
