"""Build the `zfsim._native` extension and place it in python/zfsim/.

    python sim/build.py [--release]

Plain cargo + copy, so no maturin is needed: the cdylib is just a renamed
Python extension (`_native.pyd` on Windows, `_native.so` elsewhere; the module
is built against the stable ABI, so it loads on any Python >= 3.9).
"""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    release = "--release" in sys.argv[1:]
    cmd = ["cargo", "build", "--manifest-path", str(HERE / "Cargo.toml")]
    if release:
        cmd.append("--release")
    subprocess.run(cmd, check=True)

    out = HERE / "target" / ("release" if release else "debug")
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
