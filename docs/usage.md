# Usage Guide

This document provides detailed usage examples for the Obfuscator tool.

## Command Line Interface

The Obfuscator tool provides a command-line interface (CLI) for easy integration with your workflow.

### Interactive Mode

The tool supports an interactive mode that will guide you through the process by asking for inputs step-by-step:

```bash
# Run any command without arguments to enter interactive mode
obfuscator batch-anonymize
```

The interactive mode will:
1. Prompt you for required inputs (directories, files)
2. Ask for optional parameters with sensible defaults
3. Create any necessary directories automatically
4. Provide guidance during the process

This is especially helpful for new users or when you don't want to remember all command options.

### Basic Anonymization

To anonymize a single CSV file:

```bash
obfuscator anonymize input.csv output.csv
```

By default, this will:
1. Automatically detect column data types
2. Anonymize the data while preserving format
3. Generate a mapping file named `output_mapping.pkl`

### De-anonymization

To restore original data from an anonymized file:

```bash
obfuscator deanonymize anonymized.csv restored.csv --mapping anonymized_mapping.pkl
```

This requires the mapping file created during anonymization.

### Batch Processing

To anonymize multiple CSV files in a directory:

```bash
obfuscator batch-anonymize input_dir/ output_dir/
```

This will process all CSV files in `input_dir` and save the anonymized versions to `output_dir`.

To de-anonymize multiple files:

```bash
obfuscator batch-deanonymize anonymized_dir/ restored_dir/ --mapping mapping.pkl
```

### Additional Options

#### Specifying Column Types

You can provide a JSON file with column type definitions:

```bash
obfuscator anonymize input.csv output.csv --column-types column_types.json
```

The column types JSON file should have this structure:

```json
{
  "customer_id": "uuid",
  "phone_number": "phone",
  "email": "email",
  "signup_date": "datetime",
  "customer_name": "name"
}
```

Available data types:
- `uuid`: UUID format
- `email`: Email addresses
- `phone`: Phone numbers
- `name`: Personal names
- `address`: Physical addresses
- `ip`: IP addresses (v4 or v6)
- `datetime`: Date and time values
- `boolean`: Boolean values
- `integer`: Integer numbers
- `float`: Floating-point numbers
- `json`: JSON-formatted strings
- `geography`: Geographic coordinates
- `binary`: Binary data
- `string`: Generic strings (default)

#### Setting a Random Seed

For reproducible anonymization:

```bash
obfuscator anonymize input.csv output.csv --seed 42
```

## Python API

The Obfuscator tool can also be used as a Python library.

### Basic Example

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
```

### De-anonymization Example

```python
from obfuscator.obfuscator import DataAnonymizer
import pandas as pd

# Initialize anonymizer with mapping file
deanonymizer = DataAnonymizer(mapping_file='mappings.pkl')

# Load anonymized data
anonymized_df = pd.read_csv('anonymized_data.csv')

# De-anonymize data
original_df = deanonymizer.deanonymize_dataframe(anonymized_df)

# Save restored data
original_df.to_csv('restored_data.csv', index=False)
```

### Working with Column Types

```python
from obfuscator.obfuscator import DataAnonymizer
import pandas as pd

# Initialize anonymizer
anonymizer = DataAnonymizer()

# Load data
df = pd.read_csv('data.csv')

# Define column types
column_types = {
    'id': 'uuid',
    'email': 'email',
    'phone': 'phone',
    'name': 'name',
    'created_at': 'datetime',
    'active': 'boolean',
    'score': 'float'
}

# Anonymize data with specified column types
anonymized_df = anonymizer.anonymize_dataframe(df, column_types)
```

## Tips and Best Practices

1. **Always save your mapping files**: Without them, you cannot reverse the anonymization.

2. **Set a random seed** for reproducible results when needed.

3. **Inspect your data before anonymization**: Understanding column data types will help the tool make better decisions.

4. **Combine with other tools**: You can use Obfuscator as part of data pipelines, integrating with ETL processes.

5. **Secure your mapping files**: These files contain the relationship between original and anonymized data and should be protected.