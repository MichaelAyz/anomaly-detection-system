import re

# PATCH 1: blocker.py
file1 = '/home/ubuntu/hng-detector/detector/blocker.py'
with open(file1, 'r') as f:
    c1 = f.read()

match = re.search(r'(?s)([ \t]+)audit_msg = \(\n[ \t]+f"\[\{timestamp_str\}\] BAN \{ip\} \| \{reason\}.*?\)', c1)
if match:
    indent = match.group(1)
    new_str = indent + "audit_msg = (\n" + indent + "    f\"[{timestamp_str}] BAN ip={ip} | condition={reason} | \"\n" + indent + "    f\"rate={rate:.2f}rps | baseline={baseline:.2f}rps | duration={dur_str}\"\n" + indent + ")"
    c1 = c1[:match.start()] + new_str + c1[match.end():]
    with open(file1, 'w') as f:
        f.write(c1)
    print("blocker.py patched.")
else:
    print("Could not find blocker.py pattern.")

# PATCH 2: baseline.py
file2 = '/home/ubuntu/hng-detector/detector/baseline.py'
with open(file2, 'r') as f:
    c2 = f.read()

match = re.search(r'(?s)([ \t]+)audit_msg = \(\n[ \t]+f"\[\{timestamp_str\}\] RECALCULATE -.*?\)', c2)
if match:
    indent = match.group(1)
    new_str = indent + "audit_msg = (\n" + indent + "    f\"[{timestamp_str}] BASELINE_RECALC | \"\n" + indent + "    f\"effective_mean={self.mean:.2f}rps | \"\n" + indent + "    f\"effective_stddev={self.stddev:.2f} | \"\n" + indent + "    f\"samples={sample_count} | source={source}\"\n" + indent + ")"
    c2 = c2[:match.start()] + new_str + c2[match.end():]
    with open(file2, 'w') as f:
        f.write(c2)
    print("baseline.py patched.")
else:
    print("Could not find baseline.py pattern.")

# PATCH 3: unbanner.py
file3 = '/home/ubuntu/hng-detector/detector/unbanner.py'
with open(file3, 'r') as f:
    c3 = f.read()

if 'from datetime import datetime' not in c3:
    c3 = 'from datetime import datetime\n' + c3

c3 = re.sub(
    r'(self\.config = yaml\.safe_load\(f\))',
    r"\1\n        self.audit_log_path = self.config.get('audit_log_path', '/var/log/hng-detector/audit.log')",
    c3
)

match_unban = re.search(r'([ \t]+)self\.notifier\.send_unban_alert', c3)
if match_unban:
    ind = match_unban.group(1)
    unban_code = f"""
{ind}timestamp_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
{ind}audit_msg = (
{ind}    f"[{{timestamp_str}}] UNBAN ip={{ip}} | "
{ind}    f"ban_count={{ban_info['ban_count']}} | "
{ind}    f"next_duration={{next_duration}}min"
{ind})
{ind}try:
{ind}    with open(self.audit_log_path, 'a') as f:
{ind}        f.write(audit_msg + "\\n")
{ind}except Exception as e:
{ind}    logger.error(f"Failed to write unban audit log: {{e}}")"""
    c3 = re.sub(r'([ \t]+)(self\.notifier\.send_unban_alert[^)]*\))', r'\1\2' + unban_code, c3)

match_perm = re.search(r'([ \t]+)self\.notifier\.send_permanent_ban_alert', c3)
if match_perm:
    ind = match_perm.group(1)
    perm_code = f"""
{ind}timestamp_str = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
{ind}audit_msg = (
{ind}    f"[{{timestamp_str}}] PERMANENT_BAN ip={{ip}} | "
{ind}    f"ban_count={{ban_info['ban_count']}}"
{ind})
{ind}try:
{ind}    with open(self.audit_log_path, 'a') as f:
{ind}        f.write(audit_msg + "\\n")
{ind}except Exception as e:
{ind}    logger.error(f"Failed to write permanent ban audit log: {{e}}")"""
    c3 = re.sub(r'([ \t]+)(self\.notifier\.send_permanent_ban_alert[^)]*\))', r'\1\2' + perm_code, c3)

with open(file3, 'w') as f:
    f.write(c3)
print("unbanner.py patched.")
