#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

setup(
    name="deathpy",
    version="1.0.0",
    description="WiFi Deauthentication Attack Program",
    author="Rofi (Fixploit03)",
    author_email="fixploit03@gmail.com",
    url="https://github.com/fixploit03/deathpy",
    license="MIT",

    scripts=["src/deathpy"],

    install_requires=[
        "scapy>=2.4.5",
        "termcolor>=2.4.0",
    ],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Intended Audience :: Education",
    ],

    python_requires=">=3.6",
    platforms=["Linux"],
)
