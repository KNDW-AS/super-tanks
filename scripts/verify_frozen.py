#!/usr/bin/env python3
"""
verify_frozen.py - Mechanical lock verification for Super Tanks

Verifies that all FROZEN files match their recorded checksums.
Exit code 0 = all clear, 1 = tampering detected
"""

import json
import hashlib
import sys
from pathlib import Path

def calculate_sha256(filepath: Path) -> str:
    """Calculate SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_frozen():
    """Verify all FROZEN files against manifest."""
    manifest_path = Path(__file__).parent.parent / "core_locked" / "FROZEN_MANIFEST.json"
    
    if not manifest_path.exists():
        print("🔴 ERROR: FROZEN_MANIFEST.json not found!")
        return False
    
    with open(manifest_path) as f:
        manifest = json.load(f)
    
    print(f"🔒 Super Tanks Frozen File Verification")
    print(f"   Commit: {manifest['git_commit']}")
    print(f"   Locked: {manifest['created']}")
    print()
    
    all_valid = True
    base_path = Path(__file__).parent.parent
    
    for file_info in manifest['frozen_files']:
        filepath = base_path / file_info['path']
        expected_hash = file_info['sha256']
        
        if not filepath.exists():
            print(f"🔴 MISSING: {file_info['path']}")
            all_valid = False
            continue
        
        actual_hash = calculate_sha256(filepath)
        
        if actual_hash == expected_hash:
            print(f"✅ VALID: {file_info['path']}")
        else:
            print(f"🔴 TAMPERED: {file_info['path']}")
            print(f"   Expected: {expected_hash[:16]}...")
            print(f"   Actual:   {actual_hash[:16]}...")
            all_valid = False
    
    print()
    if all_valid:
        print("🔒 ALL FROZEN FILES VERIFIED - LOCK INTACT")
        return True
    else:
        print("🚨 TAMPERING DETECTED - DO NOT PROCEED")
        return False

if __name__ == "__main__":
    success = verify_frozen()
    sys.exit(0 if success else 1)
