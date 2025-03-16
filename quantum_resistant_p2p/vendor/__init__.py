"""
Vendor initialization that makes oqs available as a regular import.
"""

import os
import sys
import platform
import ctypes
from pathlib import Path

# Don't execute more than once
if "oqs_loaded" not in globals():
    oqs_loaded = False
    
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
    
    # Check if the library exists
    if lib_path.exists():
        try:
            # Load the library directly
            if system == "Windows":
                # Add directory to PATH so the DLL can be found
                os.environ["PATH"] = f"{str(lib_path.parent)};{os.environ['PATH']}"
                # On Windows, load the DLL directly to verify it works
                oqs_dll = ctypes.windll.LoadLibrary(str(lib_path))
            elif system == "Darwin":
                # On macOS, set DYLD_LIBRARY_PATH
                os.environ["DYLD_LIBRARY_PATH"] = f"{str(lib_path.parent)}:{os.environ.get('DYLD_LIBRARY_PATH', '')}"
                # Load the library to verify it works
                oqs_lib = ctypes.cdll.LoadLibrary(str(lib_path))
            else:
                # On Linux, set LD_LIBRARY_PATH
                os.environ["LD_LIBRARY_PATH"] = f"{str(lib_path.parent)}:{os.environ.get('LD_LIBRARY_PATH', '')}"
                # Load the library to verify it works
                oqs_lib = ctypes.cdll.LoadLibrary(str(lib_path))
            
            # If we got here, the library loaded successfully
            print(f"Successfully loaded OQS library from {lib_path}")
            oqs_loaded = True
        except Exception as e:
            print(f"Error loading vendored OQS library: {e}")
            print("Using mock implementations for post-quantum algorithms")
    else:
        print(f"Vendored OQS library not found at {lib_path}")
        print("Using mock implementations for post-quantum algorithms")
    
    # Add the vendor directory to sys.path so oqs.py can be imported
    vendor_path = str(vendor_dir)
    if vendor_path not in sys.path:
        sys.path.insert(0, vendor_path)
