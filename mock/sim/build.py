"""Build the `zfsim._native` extension and place it in python/zfsim/.

    python mock/sim/build.py [--release]
    python mock/sim/build.py --version     # print the wheel version, see driver_version()

Plain cargo + copy, so no maturin is needed: the cdylib is just a renamed
Python extension (`_native.pyd` on Windows, `_native.so` elsewhere; the module
is built against the stable ABI, so it loads on any Python >= 3.9).
"""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def driver_version() -> str:
    """The driver version from kext_interface/version.txt (`[2, 0, 2, 0]`) as a
    wheel version: `2.0.2`, keeping the fourth number only when it is set."""
    text = (HERE.parents[1] / "kext_interface" / "version.txt").read_text()
    parts = [int(n) for n in text.strip().strip("[]").split(",")]
    if len(parts) == 4 and parts[3] == 0:
        parts = parts[:3]
    return ".".join(map(str, parts))


def main() -> int:
    if "--version" in sys.argv[1:]:
        print(driver_version())
        return 0
    release = "--release" in sys.argv[1:]
    cmd = ["cargo", "build", "--manifest-path", str(HERE / "Cargo.toml")]
    if release:
        cmd.append("--release")
    subprocess.run(cmd, check=True)

    # A member of the mock/ workspace: cargo builds into mock/target.
    out = HERE.parent / "target" / ("release" if release else "debug")
    if sys.platform == "win32":
        src, dst = out / "_native.dll", "_native.pyd"
    elif sys.platform == "darwin":
        src, dst = out / "lib_native.dylib", "_native.so"
    else:
        src, dst = out / "lib_native.so", "_native.so"
    target = HERE / "python" / "zfsim" / dst
    shutil.copyfile(src, target)
    print(f"built {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
