# Quantum-Resistant P2P

A secure peer-to-peer communication application with post-quantum cryptography support.

## Overview

This application provides secure messaging between peers using post-quantum cryptography algorithms. It protects against both current threats and future quantum computer attacks by implementing quantum-resistant encryption, key exchange, and digital signature algorithms.

Key features:
- Post-quantum key exchange mechanisms (ML-KEM, HQC, FrodoKEM)
- Post-quantum digital signatures (ML-DSA, SPHINCS+)
- Secure symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- Intuitive user interface for peer discovery and messaging
- End-to-end encrypted file transfer
- Secure logging with encrypted audit trails

## Requirements

- Python 3.8 or higher
- PyQt5 for the user interface
- A supported operating system: Windows, macOS, or Linux

## Installation

### Option 1: Install from Git (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/quantum_resistant_p2p.git
cd quantum_resistant_p2p

# Install the package and its dependencies
pip install .
```

### Option 2: Install in Development Mode

```bash
# Clone the repository
git clone https://github.com/yourusername/quantum_resistant_p2p.git
cd quantum_resistant_p2p

# Install in development mode
pip install -e .
```

## Running the Application

Once installed, you can run the application using:

```bash
# From the command line
python -m quantum_resistant_p2p

# Or if you installed in development mode, from the project directory:
python quantum_resistant_p2p/__main__.py
```

## Post-Quantum Cryptography Support

The application supports two modes of operation:

### 1. Native Mode (Recommended)

Native mode uses the real post-quantum cryptography implementations through the Open Quantum Safe (OQS) library, which is bundled with the application. This provides genuine post-quantum security.

When the application starts, it will automatically attempt to use native mode. You can verify if it's running in native mode by checking the status bar at the bottom of the main window, which will display "OQS: ✓" if native mode is active.

### 2. Mock Mode (Fallback)

If the native OQS library cannot be loaded for any reason, the application will automatically fall back to mock implementations. These mock implementations simulate the behavior of post-quantum algorithms but do not provide actual quantum resistance.

The status bar will show "OQS: ⚠ Mock" when running in mock mode.

## Basic Usage

1. **Start the application**

2. **Login**
   - When first starting, you'll be prompted to create a password to secure your keys
   - For subsequent launches, enter the same password

3. **Connect to Peers**
   - The application will automatically search for peers on the local network
   - Or click "Add Peer" to manually enter a peer's address
   - Select a peer from the list and click "Connect"

4. **Establish Secure Connection**
   - After connecting, click "Establish Shared Key" to perform a post-quantum key exchange
   - This creates a secure channel protected against both classical and quantum attacks

5. **Secure Messaging**
   - Type messages in the input field and press Enter or click Send
   - Use "Send File" to securely transfer files

6. **Security Settings**
   - Access "Crypto Settings" to customize which algorithms are used
   - View logs and security metrics from the Settings menu

## Troubleshooting

### OQS Library Issues

If you see "OQS: ⚠ Mock" in the status bar, the application couldn't load the native OQS library. Possible solutions:

1. Verify that the library files exist in the vendor directory:
   - Windows: `quantum_resistant_p2p/vendor/lib/windows/oqs.dll`
   - macOS: `quantum_resistant_p2p/vendor/lib/macos/liboqs.dylib`
   - Linux: `quantum_resistant_p2p/vendor/lib/linux/liboqs.so`

2. Run the OQS verification tool:
   ```bash
   python -m quantum_resistant_p2p.verify_oqs
   ```

3. If needed, rebuild the OQS library for your platform (see the Advanced section below)

### Connection Issues

If you're having trouble connecting to peers:

1. Ensure both peers are on the same network
2. Check if any firewall is blocking UDP port 8001 (discovery) or TCP port 8000 (communication)
3. Try adding the peer manually with their IP address

## Advanced: Building OQS Yourself

If you need to build the OQS library yourself:

### Windows

```bash
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE
cmake --build . --config Release --parallel 8
# Copy build\bin\Release\oqs.dll to quantum_resistant_p2p\vendor\lib\windows\
```

### macOS

```bash
brew install cmake ninja
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
cmake --build . --parallel 8
# Copy build/lib/liboqs.dylib to quantum_resistant_p2p/vendor/lib/macos/
```

### Linux

```bash
sudo apt install cmake gcc ninja-build libssl-dev
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
cmake --build . --parallel 8
# Copy build/lib/liboqs.so to quantum_resistant_p2p/vendor/lib/linux/
```

## Development

If you want to contribute to the project:

1. Fork the repository
2. Install the package in development mode: `pip install -e .`
3. Make your changes
4. Submit a pull request

## License

quantum-resistant-p2p is licensed under the MIT License; see
[LICENSE](https://github.com/DivinityQQ/quantum-resistant-p2p/blob/main/LICENSE)
for details.

## Credits

This project uses the [Open Quantum Safe (OQS)](https://openquantumsafe.org/) library for post-quantum cryptography.
