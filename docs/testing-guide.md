# Quantum-Resistant P2P Testing Guide

This guide provides instructions for testing the Quantum-Resistant P2P application, including both manual UI testing and automated algorithm compatibility testing. The application features a variety of post-quantum cryptographic algorithms, and testing ensures they work correctly and efficiently.

## Manual Testing

Manual testing involves using the application's UI to verify functionality and performance. This is the simplest way to test the application and is recommended for all users.

### Basic Functionality Test

1. **Start the application**
   ```bash
   python -m quantum_resistant_p2p
   ```

2. **Login**
   - Enter a password to secure your keys (or use your existing password)
   - Verify the main window appears with the peer list and messaging interface

3. **Connection Testing**
   - For proper testing, use one of these setups:
     - **Recommended**: Two separate computers on the same network
     - **Alternative**: A physical computer and a virtual machine
   - Start the application on both systems
   - After a moment, the peer should appear automatically in the peer list (via the UDP discovery mechanism)
   - Click the "Refresh" button if the peer doesn't appear immediately
   - **Only if automatic discovery fails**:
     - Note the IP address of one system (shown in its status bar)
     - On the other system, go to File → Connect to Peer... and enter the IP address and port (usually 8000)
   - Verify the connection is established (the peer appears in the list with "Connected" status)

4. **Key Exchange Testing**
   - Select the connected peer in the list
   - Click "Establish Shared Key" in the messaging panel
   - Verify the key exchange completes successfully ("Secure connection established" should appear)

5. **Messaging Testing**
   - Send a text message to the peer
   - Verify the message appears in both instances
   - Send messages in both directions to verify bidirectional communication

6. **File Transfer Testing**
   - Click "Send File" or go to File → Send File...
   - Select a file to send (try different sizes: small, medium, large)
   - Verify the file is received by the other instance

7. **Cryptography Settings Testing**
   - Go to Settings → Cryptography Settings...
   - Change the key exchange, symmetric, and digital signature algorithms
   - Verify keys are re-established with the new algorithms
   - Test messaging and file transfers with the new settings

### Security Features Testing

1. **Password Protection**
   - Close the application and restart it
   - Verify you need the correct password to unlock the key storage
   - Try an incorrect password and verify access is denied

2. **Logs and Metrics**
   - Go to Settings → View Logs... to check secure logging functionality
   - Go to Settings → Security Metrics... to verify metrics are being recorded
   - Go to Settings → Key Exchange History... to see key exchange records

3. **Algorithm Compatibility**
   - Test different combinations of algorithms using the Cryptography Settings dialog
   - Verify key exchanges work with different security levels

## Automated Compatibility and Performance Testing

For comprehensive testing of all algorithm combinations and performance benchmarks, use the included test script.

### Running the Test Script

The script tests all combinations of key exchange, symmetric encryption, and digital signature algorithms, measures performance, and generates a detailed report.

```bash
python -m tests.crypto_algorithms_tester --output-dir your/output/directory
```

Replace `your/output/directory` with the directory where you want the test results to be stored.

### What the Test Script Does

The script:
1. Creates two test nodes (server and client)
2. Tests all combinations of cryptographic algorithms:
   - 9 key exchange variants (ML-KEM, HQC, FrodoKEM, each at 3 security levels)
   - 2 symmetric algorithms (AES-256-GCM, ChaCha20-Poly1305)
   - 6 signature algorithms (ML-DSA, SPHINCS+, at different security levels)
3. For each combination, it tests:
   - Connection establishment
   - Key exchange
   - Basic messaging
   - File transfers of different sizes (10KB, 100KB, 1MB)
4. Measures performance metrics like key exchange time and file transfer speed
5. Generates a comprehensive report

### Test Results Analysis

Based on our latest test run (April 2025), here are the key findings:

#### Algorithm Compatibility

All 108 algorithm combinations tested successfully, demonstrating excellent interoperability. This means you can use any combination of algorithms based on your security and performance needs.

#### Key Exchange Performance

Key exchange times vary by algorithm and security level:

| Algorithm | Security Level | Average Time (sec) |
|-----------|----------------|-------------------|
| ML-KEM    | 1, 3, 5        | 0.24 - 0.25       |
| FrodoKEM  | 1              | 0.28              |
| FrodoKEM  | 3              | 0.32              |
| FrodoKEM  | 5              | 0.37              |
| HQC       | 1              | 0.30              |
| HQC       | 3              | 0.40              |
| HQC       | 5              | 0.52              |

**Note**: When using SPHINCS+ for signatures, key exchange times increase significantly due to the signature verification process, ranging from 0.7 to 1.8 seconds.

#### File Transfer Performance

File transfer speeds vary significantly based on:
1. The signature algorithm used
2. File size
3. Symmetric encryption algorithm

Top 5 performing combinations (average across all file sizes):

| Rank | Symmetric         | Signature        | Avg Speed (KB/s) |
|------|-------------------|------------------|------------------|
| 1    | ChaCha20-Poly1305 | ML-DSA (Level 2) | 7,791.17         |
| 2    | AES-256-GCM       | ML-DSA (Level 2) | 7,664.60         |
| 3    | ChaCha20-Poly1305 | ML-DSA (Level 3) | 7,495.45         |
| 4    | AES-256-GCM       | ML-DSA (Level 3) | 7,314.77         |
| 5    | AES-256-GCM       | ML-DSA (Level 5) | 7,288.28         |

Lowest performing combinations:

| Rank | Symmetric         | Signature         | Avg Speed (KB/s) |
|------|-------------------|-------------------|------------------|
| 11   | ChaCha20-Poly1305 | SPHINCS+ (Level 5)| 683.03           |
| 12   | AES-256-GCM       | SPHINCS+ (Level 5)| 682.33           |

#### File Size Impact

The impact of file size on transfer speed is significant:

**Small Files (10KB)**:
- Best: ChaCha20-Poly1305 + ML-DSA (Level 2) - 2,217.60 KB/s
- Worst: SPHINCS+ (Level 5) combinations - ~20 KB/s

**Large Files (1MB)**:
- Best: ChaCha20-Poly1305 + ML-DSA (Level 2) - 12,625.84 KB/s
- Worst: AES-256-GCM + SPHINCS+ (Level 5) - 1,824.44 KB/s

### Recommendations Based on Test Results

1. **For maximum performance**:
   - Use ML-KEM for key exchange (fastest at all security levels)
   - Use ML-DSA (Level 2) for signatures
   - ChaCha20-Poly1305 slightly outperforms AES-256-GCM for symmetic encryption

2. **For balanced security and performance**:
   - ML-KEM (Level 3) + ChaCha20-Poly1305 + ML-DSA (Level 3)
   - This combination offers NIST Level 3 security with excellent performance

3. **For high security applications**:
   - Even the highest security levels (ML-KEM Level 5, ML-DSA Level 5) perform well
   - Avoid SPHINCS+ for high-throughput applications unless you specifically need its security properties

4. **For small file transfers**:
   - The choice of signature algorithm has a much larger impact on small files
   - ML-DSA is 30-100x faster than SPHINCS+ for 10KB files

## Troubleshooting Tests

If you encounter issues during testing:

1. **Connection failures**:
   - Verify that no firewall is blocking the connections
   - Check that both instances are using different ports
   - Try restarting the application

2. **Key exchange failures**:
   - Make sure both peers are using compatible algorithms
   - Check the logs (Settings → View Logs...) for specific errors

3. **Test script failures**:
   - Ensure you have all required dependencies installed
   - Check permissions for the output directory
   - Look for error messages in the console output

## Reporting Issues

If you discover bugs or issues during testing, please report them on the GitHub issue tracker with:

1. Detailed steps to reproduce the issue
2. Your operating system and Python version
3. Logs from the application
4. Test results (if using the automated test script)

Happy testing!
