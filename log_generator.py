import os
import json
import uuid
import random
from datetime import datetime, timezone

# Config
OUTPUT_DIR = r"C:\\Users\\Palla\\aimlmcpser\\logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HOSTNAMES = ["LTZ555555", "CORP-PC01", "DEV-MACHINE"]
USERNAMES = ["Z055555", "admin", "user1"]
FILENAMES = ["wpscloudsvr.exe", "powershell.exe", "rundll32.exe"]
SCENARIOS = ["suspicious_activity", "normal_operation"]

# Generate single full-format log

def generate_log():
    hostname = random.choice(HOSTNAMES)
    username = random.choice(USERNAMES)
    filename = random.choice(FILENAMES)

    return {
        "cid": str(uuid.uuid4().hex),
        "created_timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_id": f"ldt:{uuid.uuid4().hex}:601307860240",
        "device": {
            "device_id": uuid.uuid4().hex,
            "cid": str(uuid.uuid4().hex),
            "agent_load_flags": "1",
            "agent_local_time": datetime.now(timezone.utc).isoformat(),
            "agent_version": "7.24.19607.0",
            "bios_manufacturer": "Dell Inc.",
            "bios_version": "1.7.1",
            "config_id_base": "65994767",
            "config_id_build": "19607",
            "config_id_platform": "3",
            "external_ip": "125.21.240.2",
            "hostname": hostname,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_login_timestamp": datetime.now(timezone.utc).isoformat(),
            "last_login_user": username,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "local_ip": f"192.168.1.{random.randint(2, 254)}",
            "mac_address": ":".join(f"{random.randint(0, 255):02x}" for _ in range(6)),
            "machine_domain": "india.xyz.abc",
            "major_version": "10",
            "minor_version": "0",
            "os_version": "Windows 11",
            "ou": ["Computers1"],
            "platform_id": "0",
            "platform_name": "Windows",
            "product_type": "1",
            "product_type_desc": "Workstation",
            "site_name": "Noida",
            "status": "normal",
            "system_manufacturer": "Dell Inc.",
            "system_product_name": "Latitude 3400",
            "groups": [str(uuid.uuid4().hex)],
            "modified_timestamp": datetime.now(timezone.utc).isoformat()
        },
        "behaviors": [
            {
                "device_id": uuid.uuid4().hex,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "template_instance_id": "98",
                "behavior_id": "41004",
                "filename": filename,
                "filepath": f"C:\\Program Files\\{filename}",
                "alleged_filetype": "exe",
                "cmdline": f"C:\\Program Files\\{filename} /run",
                "scenario": random.choice(SCENARIOS),
                "objective": "Falcon Detection Method",
                "tactic": "Custom Intelligence",
                "tactic_id": "CSTA0005",
                "technique": "Indicator of Attack",
                "technique_id": "CST0004",
                "display_name": "CustomIOAWinLowest",
                "description": "A process triggered an informational severity custom rule.",
                "severity": random.randint(1, 10),
                "confidence": random.choice([90, 95, 100]),
                "ioc_type": "hash_sha256",
                "ioc_value": uuid.uuid4().hex,
                "ioc_source": "library_load",
                "ioc_description": f"Suspicious execution of {filename}",
                "user_name": username,
                "user_id": f"S-1-5-{random.randint(1000000000, 9999999999)}",
                "control_graph_id": f"ctg:{uuid.uuid4().hex}:601307860240",
                "triggering_process_graph_id": f"pid:{uuid.uuid4().hex}:{random.randint(1000000000000, 2000000000000)}",
                "sha256": uuid.uuid4().hex,
                "md5": uuid.uuid4().hex[:32],
                "parent_details": {
                    "parent_sha256": uuid.uuid4().hex,
                    "parent_md5": uuid.uuid4().hex[:32],
                    "parent_cmdline": "svchost.exe -k netsvcs",
                    "parent_process_graph_id": f"pid:{uuid.uuid4().hex}:{random.randint(1000000000000, 2000000000000)}"
                },
                "pattern_disposition": 2048,
                "pattern_disposition_details": {
                    "process_blocked": True,
                    "operation_blocked": False,
                    "quarantine_file": False
                },
                "rule_instance_id": "98",
                "rule_instance_version": 3
            }
        ],
        "email_sent": False,
        "first_behavior": datetime.now(timezone.utc).isoformat(),
        "last_behavior": datetime.now(timezone.utc).isoformat(),
        "max_confidence": 100,
        "max_severity": 10,
        "max_severity_displayname": "Informational",
        "show_in_ui": True,
        "status": "new",
        "hostinfo": {
            "active_directory_dn_display": ["Computers1"],
            "domain": ""
        },
        "seconds_to_triaged": 0,
        "seconds_to_resolved": 0,
        "behaviors_processed": [
            f"pid:{uuid.uuid4().hex}:{random.randint(1000000000000, 2000000000000)}:41004"
        ],
        "date_updated": datetime.now(timezone.utc).isoformat()
    }

# Generate N files
NUM_FILES = 10
for i in range(NUM_FILES):
    data = [generate_log() for _ in range(random.randint(1, 3))]  # 1–3 logs per file
    with open(f"{OUTPUT_DIR}/log_{i+1:02}.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"✅ Saved: log_{i+1:02}.json")