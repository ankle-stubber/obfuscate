# Project Notes for Claude

This document contains notes about the Obfuscator project structure and important commands.

## Project Structure

The project is organized as follows:

```
obfuscator/
├── LICENSE
├── README.md
├── CLAUDE.md
├── setup.py
├── obfuscator/
│   ├── __init__.py
│   └── obfuscator/
│       ├── __init__.py
│       ├── anonymizer.py
│       ├── cli.py
│       ├── detectors.py
│       └── transformers.py
├── tests/
│   └── test_anonymizer.py
└── docs/
    └── usage.md
```

## Key Components

- **anonymizer.py**: Contains the main `DataAnonymizer` class that handles anonymization and de-anonymization of data.
- **detectors.py**: Contains the `DataTypeDetector` class for automatically identifying data types.
- **transformers.py**: Contains functions for anonymizing different data types while preserving format.
- **cli.py**: Implements the command-line interface for the tool.

## Development Commands

### Running Tests

```bash
python -m unittest discover tests
```

### Building the Package

```bash
python setup.py sdist bdist_wheel
```

### Installing in Development Mode

```bash
pip install -e .
```

### Running the CLI

```bash
# After installing the package
obfuscator anonymize input.csv output.csv

# Or directly
python -m obfuscator.obfuscator.cli anonymize input.csv output.csv
```

## Design Decisions

1. **Modularity**:
   - The code is separated into logical modules: anonymization core, type detection, transformations, and CLI.
   - This makes it easier to maintain and extend the codebase.

2. **Format Preservation**:
   - Each anonymization function is designed to maintain the exact format and character count of the original data.
   - This ensures that applications consuming the anonymized data don't break due to format changes.

3. **Reversibility**:
   - All transformations are stored in mapping dictionaries, allowing for complete reversal of the anonymization.
   - This is essential for testing and validation scenarios.

4. **Type Detection**:
   - The tool uses both column name hints and data pattern recognition to determine data types.
   - This reduces the need for manual type specification.

5. **Extensibility**:
   - New data types and anonymization methods can be easily added to the transformers module.
   - The core anonymizer class doesn't need to change to support new types.