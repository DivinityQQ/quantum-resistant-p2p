# Development Guide

## Project Structure

```
quantum_resistant_p2p/
├── app/
│   ├── __init__.py
│   ├── messaging.py
│   └── logging.py
├── crypto/
│   ├── __init__.py
│   ├── key_exchange.py
│   ├── signatures.py
│   ├── symmetric.py
│   └── key_storage.py
├── networking/
│   ├── __init__.py
│   ├── p2p_node.py
│   └── discovery.py
├── ui/
│   ├── __init__.py
│   ├── main_window.py
│   └── ...
├── utils/
│   ├── __init__.py
│   └── secure_file.py
└── __init__.py
```

## Development Setup

If you want to contribute to the project:

1. Fork the repository
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/quantum-resistant-p2p.git
   cd quantum-resistant-p2p
   ```
3. Create and activate a virtual environment within the project directory: 
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
4. Install the package in development mode: 
   ```bash
   pip install -e .
   ```
5. Make your changes
6. Submit a pull request

## Coding Guidelines

- Follow PEP 8 style guidelines
- Use Google-style docstrings
- Include type hints for all functions and methods
- Write unit tests for all new functionality