
import sys
sys.path.append(r"/root/global_ca_monitor")

import json
import requests
from datetime import datetime, timezone
from app import app
from app.config.scan_config import CTScanConfig
from app.utils.type import ScanType
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate

log_address = "oak.ct.letsencrypt.org/2024h1"

# get the total entry num
header_request = f"https://{log_address}/ct/v1/get-sth"
print("start")
try:
    response = requests.get(header_request, verify=True)
    if response.status_code == 200:
        size = json.loads(response.text)['tree_size']
        print(f"Tree size: {size}")
    else:
        print("Failed to retrieve tree size")
        exit(0)
except Exception as e:
    print(f"{e}")
    exit(0)

print("start")
with app.app_context():
    scan_type = ScanType(ScanType.SCAN_BY_CT)
    scan_args = {
        'SCAN_PROCESS_NAME': "oak 2024h1 60M-70M",
        'SCAN_TIMEOUT' : 2,
        'MAX_RETRY' : 10,
        'CT_LOG_ADDRESS' : log_address,
        'WINDOW_SIZE' : 20,
        'SAVE_CHUNK_SIZE' : 20000,
        'ENTRY_START' : 60000000,
        'ENTRY_END' : 70000000
        #'ENTRY_END' : size
    }

    config = CTScanConfig(**scan_args)
    task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
    g_manager.start_submitted_tasks()
