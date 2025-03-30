"""
Setup script for the Obfuscator package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="obfuscator",
    version="0.1.0",
    author="Obfuscator Team",
    author_email="info@example.com",
    description="A data anonymization tool that preserves format and character count",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/obfuscator",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "numpy>=1.19.0",
        "pandas>=1.0.0",
    ],
    entry_points={
        'console_scripts': [
            'obfuscator=obfuscator.obfuscator.cli:main',
        ],
    },
)