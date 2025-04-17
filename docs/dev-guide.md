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

### Prerequisites

- Python 3.8 or higher
- Qt libraries (for PyQt5)

### Environment Setup

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

## Coding Guidelines

- Follow PEP 8 style guidelines
- Use Google-style docstrings
- Include type hints for all functions and methods
- Write unit tests for all new functionality

## Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=quantum_resistant_p2p
```

## Documentation

Update documentation when you make changes:

```bash
# Generate updated documentation
mkdocs build

# Serve documentation locally
mkdocs serve
```