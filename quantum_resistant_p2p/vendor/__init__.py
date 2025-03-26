"""
Vendor initialization that makes oqs available as a regular import.
"""

import os
import sys
import platform
import ctypes
from pathlib import Path

# Get the path to the vendored OQS libraries
vendor_dir = Path(__file__).parent

# Determine which binary to use based on platform
system = platform.system()
if system == "Windows":
    lib_path = vendor_dir / "lib" / "windows" / "oqs.dll"
    lib_name = "oqs.dll"
elif system == "Darwin":  # macOS
    lib_path = vendor_dir / "lib" / "macos" / "liboqs.dylib"
    lib_name = "liboqs.dylib"
else:  # Linux/Unix
    lib_path = vendor_dir / "lib" / "linux" / "liboqs.so"
    lib_name = "liboqs.so"

# Load the library
try:
    # Load library for appropriate platform
    if system == "Windows":
        # Add directory to PATH so the DLL can be found
        os.environ["PATH"] = f"{str(lib_path.parent)};{os.environ['PATH']}"
        # Load the DLL directly
        oqs_dll = ctypes.windll.LoadLibrary(str(lib_path))
    elif system == "Darwin":
        # On macOS, set DYLD_LIBRARY_PATH
        os.environ["DYLD_LIBRARY_PATH"] = f"{str(lib_path.parent)}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"
        # Load the library
        oqs_lib = ctypes.cdll.LoadLibrary(str(lib_path))
    else:
        # On Linux, set LD_LIBRARY_PATH
        os.environ["LD_LIBRARY_PATH"] = f"{str(lib_path.parent)}:{os.environ.get('LD_LIBRARY_PATH', '')}"
        # Load the library
        oqs_lib = ctypes.cdll.LoadLibrary(str(lib_path))
    
    # Library loaded successfully
    print(f"Found vendored OQS library at {lib_path}")
    
except Exception as e:
    # We expect this to never happen since the library is vendored,
    # but include error handling just in case
    print(f"Fatal error: Unable to load vendored OQS library: {e}")
    raise RuntimeError(f"Fatal error: Unable to load required OQS library from {lib_path}: {e}")

# Add the vendor directory to sys.path so oqs.py can be found
vendor_path = str(vendor_dir)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)