# User Guide

## Installation

### Installation with Virtual Environment (Recommended)

It's recommended to use a virtual environment to avoid conflicts with other Python packages. Here's how to set up and install the application:

```bash
# First, clone the repository
git clone https://github.com/DivinityQQ/quantum-resistant-p2p.git
cd quantum_resistant_p2p

# Create a virtual environment inside the project directory
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

Your command prompt should now show `(venv)` at the beginning, indicating the virtual environment is active. All pip commands will now install packages into this isolated environment.

### Option 1: Standard Installation

```bash
# With the virtual environment activated and while in the quantum_resistant_p2p directory:
pip install .
```

### Option 2: Development Mode Installation

```bash
# With the virtual environment activated and while in the quantum_resistant_p2p directory:
pip install -e .
```

### Deactivating the Virtual Environment

When you're done using the application, you can deactivate the virtual environment:

```bash
deactivate
```

## Running the Application

Once installed, you can run the application using:

```bash
# Make sure your virtual environment is activated first
# (You should see (venv) at the beginning of your command prompt)

# From the quantum_resistant_p2p directory:
python -m quantum_resistant_p2p
```

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