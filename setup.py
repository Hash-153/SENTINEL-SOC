#!/usr/bin/env python3
"""Setup script for Sentinel Security Platform."""

from setuptools import setup, find_packages

setup(
    name="sentinel-nids-siem",
    version="1.0.0",
    description="Enterprise Network Intrusion Detection & SIEM Platform",
    author="Security Engineering Team",
    packages=find_packages(include=["sentinel*"]),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "sentinel=sentinel.daemon.cli:main",
        ],
    },
)
