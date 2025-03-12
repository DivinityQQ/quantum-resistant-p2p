from setuptools import setup, find_packages

setup(
    name="quantum_resistant_p2p",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "asyncio>=3.4.3",
        "aiohttp>=3.8.1",
        "qasync>=0.22.0",
        "cryptography>=37.0.4",
        "oqs>=0.10.2",
        "pynacl>=1.5.0",
        "PyQt5>=5.15.6",
        "pyyaml>=6.0",
        "python-dotenv>=0.20.0",
        "structlog>=21.5.0",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="P2P application with post-quantum cryptography",
    keywords="p2p, post-quantum, cryptography, secure communication",
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
