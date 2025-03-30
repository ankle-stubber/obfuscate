# Obfuscator

A comprehensive data anonymization tool that preserves format and character count while anonymizing sensitive data in CSV files.

## Features

- **Format Preservation**: Each field keeps the same format and character count as the original.
- **One-to-One Mapping**: The same input value always maps to the same anonymized value.
- **Reversible Anonymization**: All transformations can be reversed using the mapping file.
- **Type Detection**: Automatically identifies data types based on column names and content patterns.
- **Batch Processing**: Process multiple files in a single operation.

## Supported Data Types

- UUIDs
- Strings (including names, addresses)
- Emails
- Phone numbers
- IP addresses
- Dates and timestamps
- Numeric types (integers, floats)
- Boolean values
- Geographic coordinates
- JSON data
- Binary data

## Installation

```bash
# From PyPI
pip install obfuscator

# From source
git clone https://github.com/yourusername/obfuscator.git
cd obfuscator
pip install -e .
```

## Usage

### Interactive Mode

All commands support interactive mode, which prompts you for inputs step-by-step:

```bash
obfuscator batch-anonymize
```

The tool will prompt you for:
- Input directory path
- Output directory path
- File pattern to match
- Mapping file path
- Other options

This makes it easier to use without remembering all command-line parameters.

### Basic Anonymization

```bash
obfuscator anonymize customer_data.csv anonymized_data.csv
```

This will:
- Detect column types automatically
- Create anonymized data with the same format
- Save a mapping file for later de-anonymization

### De-anonymization

```bash
obfuscator deanonymize anonymized_data.csv restored_data.csv --mapping anonymized_data_mapping.pkl
```

This will:
- Use the mapping file to restore the original values
- Generate a restored CSV file identical to the original

### Batch Processing

```bash
obfuscator batch-anonymize input_data/ anonymized_data/ --mapping combined_mapping.pkl
```

This will:
- Process all CSV files in the input directory
- Save anonymized files to the output directory
- Create a single mapping file for all transformations

### Customizing Column Types

You can create a JSON file to specify exact types for columns:

```json
{
  "customer_id": "uuid",
  "phone_number": "phone",
  "email": "email",
  "signup_date": "datetime",
  "customer_name": "name"
}
```

Then use it with:

```bash
obfuscator anonymize input.csv output.csv --column-types column_types.json
```

## Python API

You can also use the library programmatically:

```python
from obfuscator.obfuscator import DataAnonymizer
import pandas as pd

# Initialize anonymizer
anonymizer = DataAnonymizer(seed=42)

# Load data
df = pd.read_csv('data.csv')

# Anonymize data
anonymized_df = anonymizer.anonymize_dataframe(df)

# Save anonymized data
anonymized_df.to_csv('anonymized_data.csv', index=False)

# Save mappings for later de-anonymization
anonymizer.save_mappings('mappings.pkl')

# Later, to de-anonymize:
deanonymizer = DataAnonymizer(mapping_file='mappings.pkl')
original_df = deanonymizer.deanonymize_dataframe(anonymized_df)
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.