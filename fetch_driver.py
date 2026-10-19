"""Fetch WinRing0x64.dll/.sys and verify them against the audited hashes.

The audited hashes come from the upstream repo's own driver_probe.json, which
recorded them when the files were copied unchanged from the author's tool dir.

Expected (from driver_probe.json):
  DLL sha256 a746fd5728e7485f741cc330a279674bc8590b1b8007d8614046c49f58698485
  SYS sha256 11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent / "driver"
OUT.mkdir(parents=True, exist_ok=True)

BASE = ("https://raw.githubusercontent.com/"
        "Zcodeoooo/JiaoLong16Pro-Battery-threshold/main/Windows/")

EXPECTED = {
    "WinRing0x64.dll": "a746fd5728e7485f741cc330a279674bc8590b1b8007d8614046c49f58698485",
    "WinRing0x64.sys": "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5",
}

# also confirm the repo's recorded blob sha for each file, if reachable
REPO_BLOB = {
    "WinRing0x64.dll": "4a48c7a1f6c9945906e9507fce4077facb69821a",
    "WinRing0x64.sys": "197c255adea745c8a78f529c8a38a3ceaf68711d",
}


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def main():
    ok = True
    for name, want in EXPECTED.items():
        dest = OUT / name
        if dest.exists():
            raw = dest.read_bytes()
        else:
            req = urllib.request.Request(BASE + name, headers={"User-Agent": "dsh-audit"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
            dest.write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
        blob = git_blob_sha(raw)
        good = sha == want
        blob_good = blob == REPO_BLOB[name]
        ok &= good and blob_good
        print(f"{name}: {len(raw)} bytes")
        print(f"  sha256    {sha}  {'MATCH' if good else 'MISMATCH'} (expected {want})")
        print(f"  git blob  {blob}  {'MATCH' if blob_good else 'MISMATCH'}")
    print("driver files verified" if ok else "DRIVER VERIFICATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
