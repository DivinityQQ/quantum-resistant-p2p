#!/usr/bin/env python
"""
Script to test if OQS is working properly in the current environment.
If not, it provides instructions on how to set it up.
"""

import os
import sys
import platform
import subprocess

def check_oqs_installation():
    """Check if OQS Python bindings are installed and working."""
    try:
        import oqs
        print(f"OQS Python bindings are installed (liboqs-python version: {oqs.oqs_python_version()})")
        print(f"liboqs version: {oqs.oqs_version()}")
        
        # Check if KEM mechanisms are available
        print("\nEnabled KEM mechanisms:")
        enabled_kems = oqs.get_enabled_kem_mechanisms()
        for i, kem in enumerate(enabled_kems):
            print(f"  {i+1}. {kem}")
        
        # Check if signature mechanisms are available
        print("\nEnabled signature mechanisms:")
        enabled_sigs = oqs.get_enabled_sig_mechanisms()
        for i, sig in enumerate(enabled_sigs):
            print(f"  {i+1}. {sig}")
        
        # Try creating a KEM
        print("\nTesting KEM functionality...")
        try:
            with oqs.KeyEncapsulation("ML-KEM-512") as client:
                public_key = client.generate_keypair()
                print(f"  Generated KEM keypair successfully (public key: {len(public_key)} bytes)")
            print("  KEM test successful!")
        except Exception as e:
            print(f"  Error testing KEM: {e}")
        
        # Try creating a signature
        print("\nTesting signature functionality...")
        try:
            with oqs.Signature("ML-DSA-44") as signer:
                public_key = signer.generate_keypair()
                print(f"  Generated signature keypair successfully (public key: {len(public_key)} bytes)")
            print("  Signature test successful!")
        except Exception as e:
            print(f"  Error testing signature: {e}")
        
        return True
    except ImportError:
        print("OQS Python bindings are not installed.")
        return False
    except Exception as e:
        print(f"Error initializing OQS: {e}")
        return False

def print_installation_instructions():
    """Print instructions for installing OQS."""
    system = platform.system()
    
    print("\n=== Installation Instructions ===")
    
    if system == "Windows":
        print("Installation on Windows:")
        print("1. The simplest approach is to use pre-built wheels:")
        print("   pip install liboqs-python")
        print("\n2. If that doesn't work, you'll need to build from source:")
        print("   - Install Visual Studio Build Tools with C++ support")
        print("   - Install CMake")
        print("   - Follow instructions at: https://github.com/open-quantum-safe/liboqs-python")
    
    elif system == "Darwin":  # macOS
        print("Installation on macOS:")
        print("1. Install dependencies using homebrew:")
        print("   brew install cmake ninja openssl")
        print("2. Install OQS Python bindings:")
        print("   pip install liboqs-python")
        print("\nIf you encounter issues, you may need to build from source:")
        print("   See: https://github.com/open-quantum-safe/liboqs-python")
    
    else:  # Linux
        print("Installation on Linux:")
        print("1. Install dependencies:")
        print("   sudo apt update")
        print("   sudo apt install cmake gcc ninja-build libssl-dev python3-dev")
        print("2. Install OQS Python bindings:")
        print("   pip install liboqs-python")
        print("\nIf you encounter issues, you may need to build from source:")
        print("   See: https://github.com/open-quantum-safe/liboqs-python")
    
    print("\nFor more detailed instructions, visit:")
    print("https://github.com/open-quantum-safe/liboqs-python")

def check_mock_implementation():
    """Test the fallback mock implementation."""
    print("\n=== Testing Fallback Mock Implementation ===")
    
    try:
        # Import directly from project
        sys.path.insert(0, os.path.abspath('.'))
        from quantum_resistant_p2p.crypto.key_exchange import KyberKeyExchange, NTRUKeyExchange
        from quantum_resistant_p2p.crypto.signatures import DilithiumSignature, SPHINCSSignature
        
        # Test key exchange
        print("Testing KyberKeyExchange mock...")
        kyber = KyberKeyExchange(security_level=3)
        pub_key, priv_key = kyber.generate_keypair()
        ciphertext, shared_secret1 = kyber.encapsulate(pub_key)
        shared_secret2 = kyber.decapsulate(priv_key, ciphertext)
        if shared_secret1 == shared_secret2:
            print("  Mock KyberKeyExchange working correctly!")
        else:
            print("  Error: Mock KyberKeyExchange not functioning properly")
        
        # Test signature
        print("Testing DilithiumSignature mock...")
        dilithium = DilithiumSignature(security_level=3)
        pub_key, priv_key = dilithium.generate_keypair()
        message = b"Test message"
        signature = dilithium.sign(priv_key, message)
        is_valid = dilithium.verify(pub_key, message, signature)
        if is_valid:
            print("  Mock DilithiumSignature working correctly!")
        else:
            print("  Error: Mock DilithiumSignature not functioning properly")
        
        return True
    except Exception as e:
        print(f"Error testing mock implementation: {e}")
        return False

def main():
    """Main function."""
    print("=== OQS Installation Checker ===")
    
    # Check if OQS is installed and working
    oqs_working = check_oqs_installation()
    
    if not oqs_working:
        print_installation_instructions()
    
    # Check the mock implementation
    mock_working = check_mock_implementation()
    
    # Summary
    print("\n=== Summary ===")
    print(f"OQS Installation: {'WORKING' if oqs_working else 'NOT WORKING'}")
    print(f"Mock Implementation: {'WORKING' if mock_working else 'NOT WORKING'}")
    
    if oqs_working:
        print("\nThe system is ready to use the real OQS implementation!")
    elif mock_working:
        print("\nThe real OQS implementation is not available, but the mock implementation works.")
        print("You can still use the application with the mock implementation.")
    else:
        print("\nNeither the real OQS implementation nor the mock implementation is working.")
        print("Please check the project setup and try again.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
