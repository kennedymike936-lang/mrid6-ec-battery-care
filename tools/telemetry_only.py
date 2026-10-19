"""Read-only telemetry snapshot. No EC access, no driver, no writes.

Used to independently corroborate the EC-reported state after 0x0E.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import transport  # noqa: E402

print(json.dumps({"windows": transport.windows_status()}, ensure_ascii=False))
print(json.dumps(transport.cim_battery_telemetry(), ensure_ascii=False))
