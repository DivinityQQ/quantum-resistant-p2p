from setuptools import setup, find_packages

setup(
    name="quantum_resistant_p2p",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "asyncio>=3.4.3",
        "aiohttp>=3.11.14",
        "qasync>=0.27.1",
        "cryptography>=44.0.2",
        "pynacl>=1.5.0",
        "PyQt5>=5.15.11",
        "pyyaml>=6.0.2",
        "python-dotenv>=1.0.1",
        "structlog>=25.2.0",
    ],
    author="DivinityQQ",
    author_email="divinityqq@gmail.com",
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
