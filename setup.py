#!/usr/bin/env python3
"""
ChatCLI Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="chatcli",
    version="2.0.0",
    author="ChatCLI Team",
    author_email="contact@chatcli.dev",
    description="Secure LAN-only chat application with file sharing and encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/chatcli",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Communications :: Chat",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "Pillow>=10.0.0",
    ],
    entry_points={
        "console_scripts": [
            "chatcli=chatcli.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
