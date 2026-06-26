Import("env")
import shutil
import os
import re

def copy_firmware(*args, **kwargs):
    """Copy firmware.bin to project root/ota/ as OTA-ready binary."""
    project_dir = env.subst("$PROJECT_DIR")
    build_dir = env.subst("$BUILD_DIR")
    src = os.path.join(build_dir, "firmware.bin")
    if not os.path.isfile(src):
        print(f"OTA: firmware.bin not found at {src}")
        return

    # Read FW_VERSION from config.h
    config_path = os.path.join(project_dir, "include", "config.h")
    version = "unknown"
    try:
        with open(config_path, "r") as f:
            for line in f:
                m = re.search(r'#define\s+FW_VERSION\s+"([^"]+)"', line)
                if m:
                    version = m.group(1)
                    break
    except IOError:
        pass

    dst_dir = os.path.join(project_dir, "ota")
    os.makedirs(dst_dir, exist_ok=True)

    # Copy as versioned name and generic name
    dst_versioned = os.path.join(dst_dir, f"firmware-v{version}.bin")
    dst_generic = os.path.join(dst_dir, "firmware.bin")
    shutil.copy2(src, dst_versioned)
    shutil.copy2(src, dst_generic)
    fsize = os.path.getsize(src)
    print(f"OTA binary: {dst_versioned} ({fsize} bytes)")

env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", copy_firmware)
