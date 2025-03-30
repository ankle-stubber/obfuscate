#!/usr/bin/env python3
"""
Data Anonymizer - A tool for anonymizing sensitive data in CSV files

This script provides functionality to anonymize and de-anonymize data while preserving
format and character counts. It supports UUIDs, PII (phone numbers, emails, names),
timestamps, and various other data types found in Snowflake SQL.

Features:
- One-to-one mapping for consistent anonymization
- Format preservation (same number of characters, same structure)
- Timestamp shifting by a consistent amount
- Support for multiple file formats
- Batch processing of multiple files
- Command-line interface

Example usage:
  # Anonymize a single CSV file
  python data_anonymizer.py anonymize input.csv anonymized.csv

  # Deanonymize a single CSV file
  python data_anonymizer.py deanonymize anonymized.csv deanonymized.csv --mapping mapping.pkl

  # Anonymize multiple CSV files
  python data_anonymizer.py batch-anonymize input_dir/ output_dir/

  # Deanonymize multiple CSV files
  python data_anonymizer.py batch-deanonymize anonymized_dir/ deanonymized_dir/ --mapping mapping.pkl
"""

import pandas as pd
import numpy as np
import uuid
import random
import string
import datetime
import re
import pickle
import hashlib
import json
import os
import glob
from typing import Dict, Any, List, Tuple, Union, Optional


class DataAnonymizer:
    """
    Class for anonymizing and deanonymizing sensitive data.
    
    Handles various data types while preserving format and maintaining
    consistent one-to-one mappings for reversibility.
    """
    
    def __init__(self, 
                 seed: Optional[int] = None, 
                 mapping_file: Optional[str] = None,
                 timestamp_shift: Optional[int] = None):
        """Initialize the anonymizer with optional seed and existing mappings."""
        # Set random seed for reproducibility
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
        
        # Load existing mappings or create new ones
        self.mappings = self._load_mappings(mapping_file) if mapping_file else {}
        
        # Initialize mapping dictionaries for different data types if not present
        self._init_mappings()
        
        # Set timestamp shift if provided or generate a new one
        if 'timestamp_shift' not in self.mappings:
            self.mappings['timestamp_shift'] = timestamp_shift or random.randint(86400*30, 86400*365)  # Between 30 days and 1 year
    
    def _init_mappings(self):
        """Initialize mapping dictionaries for different data types."""
        # Initialize mappings for different data types
        mapping_types = [
            'uuid', 'string', 'email', 'phone', 'name', 'address', 
            'ip', 'boolean', 'numeric', 'geography', 'binary'
        ]
        
        for mapping_type in mapping_types:
            if mapping_type not in self.mappings:
                self.mappings[mapping_type] = {}
    
    def _load_mappings(self, mapping_file: str) -> Dict[str, Any]:
        """Load mappings from a file."""
        try:
            with open(mapping_file, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error loading mapping file: {e}")
            return {}
    
    def save_mappings(self, mapping_file: str) -> None:
        """Save mappings to a file."""
        with open(mapping_file, 'wb') as f:
            pickle.dump(self.mappings, f)
    
    def anonymize_dataframe(self, df: pd.DataFrame, column_types: Optional[Dict[str, str]] = None) -> pd.DataFrame:
        """
        Anonymize a pandas DataFrame.
        
        Args:
            df: Input DataFrame
            column_types: Optional dictionary mapping column names to their types
                        (if not provided, types will be inferred)
        
        Returns:
            Anonymized DataFrame
        """
        # Make a copy to avoid modifying the original
        anon_df = df.copy()
        
        # Detect column types if not provided
        if column_types is None:
            column_types = self._detect_column_types(df)
        
        # Apply appropriate anonymization function to each column
        for col in df.columns:
            col_type = column_types.get(col, 'string')
            anon_df[col] = self._anonymize_column(df[col], col_type)
        
        return anon_df
    
    def _detect_column_types(self, df: pd.DataFrame) -> Dict[str, str]:
        """Detect the types of each column in the DataFrame."""
        column_types = {}
        
        for col in df.columns:
            # Skip columns with all NaN values
            if df[col].isna().all():
                column_types[col] = 'null'
                continue
                
            # Get a non-null sample
            sample = df[col].dropna().iloc[0] if not df[col].dropna().empty else None
            
            # Check column name for hints
            col_lower = col.lower()
            
            # UUID detection
            if 'uuid' in col_lower or 'guid' in col_lower:
                if self._is_uuid(df[col]):
                    column_types[col] = 'uuid'
                    continue
            
            # Email detection
            if any(term in col_lower for term in ['email', 'e-mail', 'mail']):
                if self._is_email(df[col]):
                    column_types[col] = 'email'
                    continue
            
            # Phone detection
            if any(term in col_lower for term in ['phone', 'mobile', 'cell', 'tel']):
                if self._is_phone(df[col]):
                    column_types[col] = 'phone'
                    continue
            
            # Name detection
            if any(term in col_lower for term in ['name', 'firstname', 'lastname', 'fullname']):
                column_types[col] = 'name'
                continue
            
            # Address detection
            if any(term in col_lower for term in ['address', 'street', 'city', 'zip', 'postal']):
                column_types[col] = 'address'
                continue
            
            # IP address detection
            if any(term in col_lower for term in ['ip', 'ipv4', 'ipv6']):
                if self._is_ip(df[col]):
                    column_types[col] = 'ip'
                    continue
            
            # Date/Time detection
            if any(term in col_lower for term in ['date', 'time', 'timestamp']):
                if self._is_datetime(df[col]):
                    column_types[col] = 'datetime'
                    continue
            
            # Now check the data type
            if pd.api.types.is_bool_dtype(df[col]):
                column_types[col] = 'boolean'
            elif pd.api.types.is_integer_dtype(df[col]):
                column_types[col] = 'integer'
            elif pd.api.types.is_float_dtype(df[col]):
                column_types[col] = 'float'
            elif pd.api.types.is_datetime64_any_dtype(df[col]):
                column_types[col] = 'datetime'
            elif self._is_json(df[col]):
                column_types[col] = 'json'
            elif pd.api.types.is_object_dtype(df[col]):
                # Further check for specific string formats
                if self._is_uuid(df[col]):
                    column_types[col] = 'uuid'
                elif self._is_email(df[col]):
                    column_types[col] = 'email'
                elif self._is_phone(df[col]):
                    column_types[col] = 'phone'
                elif self._is_ip(df[col]):
                    column_types[col] = 'ip'
                elif self._is_datetime(df[col]):
                    column_types[col] = 'datetime'
                else:
                    column_types[col] = 'string'
            else:
                # Default to string for any other type
                column_types[col] = 'string'
        
        return column_types

    def _is_uuid(self, series: pd.Series) -> bool:
        """Check if a series contains UUID values."""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        # Check a sample of non-null values
        sample = series.dropna().head(10)
        return all(bool(re.match(pattern, str(x), re.IGNORECASE)) for x in sample)

    def _is_email(self, series: pd.Series) -> bool:
        """Check if a series contains email addresses."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        # Check a sample of non-null values
        sample = series.dropna().head(10)
        return all(bool(re.match(pattern, str(x))) for x in sample)

    def _is_phone(self, series: pd.Series) -> bool:
        """Check if a series contains phone numbers."""
        # Various phone formats
        patterns = [
            r'^\+?1?\d{10}$',  # +1XXXXXXXXXX or XXXXXXXXXX
            r'^\+?1?\d{3}[- ]?\d{3}[- ]?\d{4}$',  # XXX-XXX-XXXX or XXX XXX XXXX
            r'^\+?1?\(\d{3}\)[- ]?\d{3}[- ]?\d{4}$'  # (XXX) XXX-XXXX
        ]
        
        # Check a sample of non-null values
        sample = series.dropna().head(10)
        
        for val in sample:
            if not any(bool(re.match(pattern, str(val))) for pattern in patterns):
                return False
        
        return True

    def _is_ip(self, series: pd.Series) -> bool:
        """Check if a series contains IP addresses."""
        # IPv4 pattern
        ipv4_pattern = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        # Check a sample of non-null values
        sample = series.dropna().head(10)
        
        for val in sample:
            if not (bool(re.match(ipv4_pattern, str(val))) or bool(re.match(ipv6_pattern, str(val)))):
                return False
        
        return True

    def _is_datetime(self, series: pd.Series) -> bool:
        """Check if a series contains datetime values."""
        try:
            pd.to_datetime(series.dropna().head(10))
            return True
        except:
            return False

    def _is_json(self, series: pd.Series) -> bool:
        """Check if a series contains JSON values."""
        try:
            # Try to parse a sample as JSON
            sample = series.dropna().head(10)
            for val in sample:
                if isinstance(val, str):
                    json.loads(val)
            return True
        except:
            return False
            
    def _anonymize_column(self, series: pd.Series, col_type: str) -> pd.Series:
        """Apply appropriate anonymization based on column type."""
        # Handle null values
        if series.isna().all() or col_type == 'null':
            return series
        
        # Make a copy to avoid modifying the original
        result = series.copy()
        
        # Choose the appropriate anonymization function based on column type
        if col_type == 'uuid':
            result = result.apply(lambda x: self._anonymize_uuid(x) if not pd.isna(x) else x)
        elif col_type == 'email':
            result = result.apply(lambda x: self._anonymize_email(x) if not pd.isna(x) else x)
        elif col_type == 'phone':
            result = result.apply(lambda x: self._anonymize_phone(x) if not pd.isna(x) else x)
        elif col_type == 'name':
            result = result.apply(lambda x: self._anonymize_name(x) if not pd.isna(x) else x)
        elif col_type == 'address':
            result = result.apply(lambda x: self._anonymize_address(x) if not pd.isna(x) else x)
        elif col_type == 'ip':
            result = result.apply(lambda x: self._anonymize_ip(x) if not pd.isna(x) else x)
        elif col_type == 'datetime':
            result = result.apply(lambda x: self._anonymize_datetime(x) if not pd.isna(x) else x)
        elif col_type == 'boolean':
            result = result.apply(lambda x: self._anonymize_boolean(x) if not pd.isna(x) else x)
        elif col_type == 'integer':
            result = result.apply(lambda x: self._anonymize_integer(x) if not pd.isna(x) else x)
        elif col_type == 'float':
            result = result.apply(lambda x: self._anonymize_float(x) if not pd.isna(x) else x)
        elif col_type == 'json':
            result = result.apply(lambda x: self._anonymize_json(x) if not pd.isna(x) else x)
        elif col_type == 'geography':
            result = result.apply(lambda x: self._anonymize_geography(x) if not pd.isna(x) else x)
        elif col_type == 'binary':
            result = result.apply(lambda x: self._anonymize_binary(x) if not pd.isna(x) else x)
        else:  # Default to string
            result = result.apply(lambda x: self._anonymize_string(x) if not pd.isna(x) else x)
        
        return result
        
    def _anonymize_uuid(self, value: str) -> str:
        """Anonymize a UUID while preserving format."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['uuid']:
            return self.mappings['uuid'][value]
        
        # Generate a new UUID
        anonymized = str(uuid.uuid4())
        
        # Store in mapping
        self.mappings['uuid'][value] = anonymized
        
        return anonymized

    def _anonymize_email(self, value: str) -> str:
        """Anonymize an email address while preserving format."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['email']:
            return self.mappings['email'][value]
        
        # Split into username and domain parts
        try:
            username, domain = value.split('@')
            domain_parts = domain.split('.')
            tld = domain_parts[-1]
            domain_name = '.'.join(domain_parts[:-1])
            
            # Create random username of same length
            anon_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(len(username)))
            
            # Create random domain name of same length
            anon_domain = ''.join(random.choice(string.ascii_lowercase) for _ in range(len(domain_name)))
            
            # Construct new email
            anonymized = f"{anon_username}@{anon_domain}.{tld}"
            
        except:
            # Fallback if parsing fails
            anonymized = ''.join(random.choice(string.ascii_lowercase) for _ in range(len(value)))
        
        # Store in mapping
        self.mappings['email'][value] = anonymized
        
        return anonymized

    def _anonymize_phone(self, value: str) -> str:
        """Anonymize a phone number while preserving format."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['phone']:
            return self.mappings['phone'][value]
        
        # Keep the same formatting but replace digits
        anonymized = re.sub(r'\d', lambda _: str(random.randint(0, 9)), value)
        
        # Store in mapping
        self.mappings['phone'][value] = anonymized
        
        return anonymized

    def _anonymize_name(self, value: str) -> str:
        """Anonymize a name while preserving length and capitalization."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['name']:
            return self.mappings['name'][value]
        
        # Split into words (e.g., first name, last name)
        words = value.split()
        anonymized_words = []
        
        for word in words:
            # Preserve capitalization pattern
            chars = []
            for c in word:
                if c.isupper():
                    chars.append(random.choice(string.ascii_uppercase))
                elif c.islower():
                    chars.append(random.choice(string.ascii_lowercase))
                else:
                    chars.append(c)  # Keep non-alphabetic characters as is
            
            anonymized_words.append(''.join(chars))
        
        # Rejoin with original spacing
        anonymized = ' '.join(anonymized_words)
        
        # Store in mapping
        self.mappings['name'][value] = anonymized
        
        return anonymized

    def _anonymize_address(self, value: str) -> str:
        """Anonymize an address while preserving format and length."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['address']:
            return self.mappings['address'][value]
        
        # Replace alphabetic characters while preserving case, digits, and special characters
        chars = []
        for c in value:
            if c.isupper():
                chars.append(random.choice(string.ascii_uppercase))
            elif c.islower():
                chars.append(random.choice(string.ascii_lowercase))
            elif c.isdigit():
                chars.append(str(random.randint(0, 9)))
            else:
                chars.append(c)  # Keep special characters as is
        
        anonymized = ''.join(chars)
        
        # Store in mapping
        self.mappings['address'][value] = anonymized
        
        return anonymized

    def _anonymize_ip(self, value: str) -> str:
        """Anonymize an IP address while preserving format (IPv4 or IPv6)."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['ip']:
            return self.mappings['ip'][value]
        
        # Check if IPv4 or IPv6
        if '.' in value:  # IPv4
            octets = value.split('.')
            anonymized = '.'.join(str(random.randint(0, 255)) for _ in octets)
        else:  # IPv6
            segments = value.split(':')
            anonymized = ':'.join(format(random.randint(0, 65535), 'x').zfill(4) for _ in segments)
        
        # Store in mapping
        self.mappings['ip'][value] = anonymized
        
        return anonymized

    def _anonymize_datetime(self, value: Any) -> Any:
        """Anonymize a datetime value by applying a consistent shift."""
        try:
            # Parse to datetime if string
            if isinstance(value, str):
                dt = pd.to_datetime(value)
                # Preserve the original format
                original_format = self._detect_datetime_format(value)
            else:
                dt = pd.to_datetime(value)
                original_format = None
            
            # Apply shift (in seconds)
            shifted = dt + pd.Timedelta(seconds=self.mappings['timestamp_shift'])
            
            # Return in original format if detected
            if original_format:
                return shifted.strftime(original_format)
            
            # Otherwise return in same type as input
            if isinstance(value, str):
                return str(shifted)
            return shifted
            
        except:
            # Fall back to string anonymization if parsing fails
            return self._anonymize_string(str(value))

    def _detect_datetime_format(self, date_string: str) -> str:
        """Attempt to detect the format of a datetime string."""
        # Common formats to check
        formats = [
            '%Y-%m-%d',                    # 2023-12-31
            '%Y-%m-%d %H:%M:%S',           # 2023-12-31 23:59:59
            '%Y-%m-%d %H:%M:%S.%f',        # 2023-12-31 23:59:59.999999
            '%Y-%m-%dT%H:%M:%S',           # 2023-12-31T23:59:59
            '%Y-%m-%dT%H:%M:%S.%f',        # 2023-12-31T23:59:59.999999
            '%Y-%m-%dT%H:%M:%S%z',         # 2023-12-31T23:59:59+0000
            '%Y-%m-%dT%H:%M:%S.%f%z',      # 2023-12-31T23:59:59.999999+0000
            '%Y/%m/%d',                    # 2023/12/31
            '%Y/%m/%d %H:%M:%S',           # 2023/12/31 23:59:59
            '%d-%m-%Y',                    # 31-12-2023
            '%d/%m/%Y',                    # 31/12/2023
            '%m/%d/%Y',                    # 12/31/2023
            '%m-%d-%Y',                    # 12-31-2023
            '%b %d, %Y',                   # Dec 31, 2023
            '%B %d, %Y',                   # December 31, 2023
            '%d %b %Y',                    # 31 Dec 2023
            '%d %B %Y',                    # 31 December 2023
            '%Y%m%d',                      # 20231231
            '%Y%m%d%H%M%S',                # 20231231235959
        ]
        
        for fmt in formats:
            try:
                datetime.datetime.strptime(date_string, fmt)
                return fmt
            except ValueError:
                continue
        
        # Default format if none match
        return '%Y-%m-%d %H:%M:%S'

    def _anonymize_boolean(self, value: bool) -> bool:
        """Anonymize a boolean value (optional, can keep as is)."""
        # For consistency in anonymization, we'll randomly flip based on hash
        val_str = str(value)
        
        # Check if already in mapping
        if val_str in self.mappings['boolean']:
            return self.mappings['boolean'][val_str]
        
        # We can either keep as is or randomly flip
        # For this implementation, we'll keep as is (not sensitive)
        anonymized = value
        
        # Store in mapping
        self.mappings['boolean'][val_str] = anonymized
        
        return anonymized

    def _anonymize_integer(self, value: int) -> int:
        """Anonymize an integer value while preserving magnitude."""
        val_str = str(value)
        
        # Check if already in mapping
        if val_str in self.mappings['numeric']:
            return self.mappings['numeric'][val_str]
        
        # Keep sign and approximate magnitude, but change the value
        sign = -1 if value < 0 else 1
        magnitude = 10 ** (len(str(abs(value))) - 1)
        
        # Generate a random number with same number of digits
        if magnitude > 0:
            anonymized = sign * (random.randint(magnitude, 10 * magnitude - 1))
        else:
            anonymized = 0
        
        # Store in mapping
        self.mappings['numeric'][val_str] = anonymized
        
        return anonymized

    def _anonymize_float(self, value: float) -> float:
        """Anonymize a float value while preserving magnitude and precision."""
        val_str = str(value)
        
        # Check if already in mapping
        if val_str in self.mappings['numeric']:
            return self.mappings['numeric'][val_str]
        
        # Parse to get sign, integer part, and decimal part
        sign = -1 if value < 0 else 1
        abs_val = abs(value)
        int_part = int(abs_val)
        decimal_part = abs_val - int_part
        
        # Determine number of digits in integer part
        int_digits = len(str(int_part)) if int_part > 0 else 1
        
        # Determine precision (number of decimal places)
        str_val = str(abs_val)
        decimal_places = 0
        if '.' in str_val:
            decimal_places = len(str_val.split('.')[1])
        
        # Generate random integer part with same number of digits
        if int_digits > 1:
            new_int_part = random.randint(10 ** (int_digits - 1), 10 ** int_digits - 1)
        else:
            new_int_part = random.randint(0, 9)
        
        # Generate random decimal part with same precision
        new_decimal_part = round(random.random(), decimal_places)
        
        # Combine to create anonymized float
        anonymized = sign * (new_int_part + new_decimal_part)
        
        # Round to original precision
        anonymized = round(anonymized, decimal_places)
        
        # Store in mapping
        self.mappings['numeric'][val_str] = anonymized
        
        return anonymized

    def _anonymize_string(self, value: str) -> str:
        """Anonymize a general string while preserving length and character types."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['string']:
            return self.mappings['string'][value]
        
        # Replace with random characters while preserving case, digits, and special characters
        chars = []
        for c in value:
            if c.isupper():
                chars.append(random.choice(string.ascii_uppercase))
            elif c.islower():
                chars.append(random.choice(string.ascii_lowercase))
            elif c.isdigit():
                chars.append(str(random.randint(0, 9)))
            else:
                chars.append(c)  # Keep special characters as is
        
        anonymized = ''.join(chars)
        
        # Store in mapping
        self.mappings['string'][value] = anonymized
        
        return anonymized

    def _anonymize_json(self, value: str) -> str:
        """Anonymize a JSON string while preserving structure."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['string']:
            return self.mappings['string'][value]
        
        try:
            # Parse JSON
            data = json.loads(value)
            
            # Recursively anonymize JSON
            anonymized_data = self._anonymize_json_object(data)
            
            # Convert back to JSON string with same formatting
            anonymized = json.dumps(anonymized_data, indent=self._detect_json_indent(value))
            
            # Store in mapping
            self.mappings['string'][value] = anonymized
            
            return anonymized
        except:
            # Fall back to string anonymization if parsing fails
            return self._anonymize_string(value)

    def _anonymize_json_object(self, obj: Any) -> Any:
        """Recursively anonymize a JSON object."""
        if isinstance(obj, dict):
            return {k: self._anonymize_json_object(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._anonymize_json_object(item) for item in obj]
        elif isinstance(obj, str):
            return self._anonymize_string(obj)
        elif isinstance(obj, int):
            return self._anonymize_integer(obj)
        elif isinstance(obj, float):
            return self._anonymize_float(obj)
        elif obj is None or isinstance(obj, bool):
            return obj
        else:
            return self._anonymize_string(str(obj))
            
    # Deanonymization functions
    def deanonymize_dataframe(self, df: pd.DataFrame, original_column_types: Optional[Dict[str, str]] = None) -> pd.DataFrame:
        """
        Deanonymize a pandas DataFrame that was previously anonymized.
        
        Args:
            df: Anonymized DataFrame
            original_column_types: Optional dictionary mapping column names to their types
                                 (if not provided, types will be inferred)
        
        Returns:
            Deanonymized DataFrame
        """
        # Make a copy to avoid modifying the original
        deanon_df = df.copy()
        
        # Detect column types if not provided
        if original_column_types is None:
            original_column_types = self._detect_column_types(df)
        
        # Apply appropriate deanonymization function to each column
        for col in df.columns:
            col_type = original_column_types.get(col, 'string')
            deanon_df[col] = self._deanonymize_column(df[col], col_type)
        
        return deanon_df

    def _deanonymize_column(self, series: pd.Series, col_type: str) -> pd.Series:
        """Apply appropriate deanonymization based on column type."""
        # Handle null values
        if series.isna().all() or col_type == 'null':
            return series
        
        # Make a copy to avoid modifying the original
        result = series.copy()
        
        # Choose the appropriate deanonymization function based on column type
        if col_type == 'uuid':
            result = result.apply(lambda x: self._deanonymize_uuid(x) if not pd.isna(x) else x)
        elif col_type == 'email':
            result = result.apply(lambda x: self._deanonymize_email(x) if not pd.isna(x) else x)
        elif col_type == 'phone':
            result = result.apply(lambda x: self._deanonymize_phone(x) if not pd.isna(x) else x)
        elif col_type == 'name':
            result = result.apply(lambda x: self._deanonymize_name(x) if not pd.isna(x) else x)
        elif col_type == 'address':
            result = result.apply(lambda x: self._deanonymize_address(x) if not pd.isna(x) else x)
        elif col_type == 'ip':
            result = result.apply(lambda x: self._deanonymize_ip(x) if not pd.isna(x) else x)
        elif col_type == 'datetime':
            result = result.apply(lambda x: self._deanonymize_datetime(x) if not pd.isna(x) else x)
        elif col_type == 'boolean':
            result = result.apply(lambda x: self._deanonymize_boolean(x) if not pd.isna(x) else x)
        elif col_type == 'integer':
            result = result.apply(lambda x: self._deanonymize_integer(x) if not pd.isna(x) else x)
        elif col_type == 'float':
            result = result.apply(lambda x: self._deanonymize_float(x) if not pd.isna(x) else x)
        elif col_type == 'json':
            result = result.apply(lambda x: self._deanonymize_json(x) if not pd.isna(x) else x)
        elif col_type == 'geography':
            result = result.apply(lambda x: self._deanonymize_geography(x) if not pd.isna(x) else x)
        elif col_type == 'binary':
            result = result.apply(lambda x: self._deanonymize_binary(x) if not pd.isna(x) else x)
        else:  # Default to string
            result = result.apply(lambda x: self._deanonymize_string(x) if not pd.isna(x) else x)
        
        return result

    def _create_reverse_mappings(self):
        """Create reverse mappings for deanonymization."""
        for mapping_type in self.mappings:
            if mapping_type != 'timestamp_shift' and f"{mapping_type}_reverse" not in self.mappings:
                if mapping_type == 'binary':
                    # Special handling for binary data
                    self.mappings[f"{mapping_type}_reverse"] = {
                        hashlib.md5(v).hexdigest(): k for k, v in self.mappings[mapping_type].items()
                    }
                else:
                    # Regular mapping
                    self.mappings[f"{mapping_type}_reverse"] = {
                        v: k for k, v in self.mappings[mapping_type].items()
                    }

    def _deanonymize_uuid(self, value: str) -> str:
        """Deanonymize a UUID using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'uuid_reverse' not in self.mappings:
            self.mappings['uuid_reverse'] = {v: k for k, v in self.mappings['uuid'].items()}
        
        # Look up in reverse mapping
        return self.mappings['uuid_reverse'].get(value, value)

    def _deanonymize_email(self, value: str) -> str:
        """Deanonymize an email using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'email_reverse' not in self.mappings:
            self.mappings['email_reverse'] = {v: k for k, v in self.mappings['email'].items()}
        
        # Look up in reverse mapping
        return self.mappings['email_reverse'].get(value, value)

    def _deanonymize_phone(self, value: str) -> str:
        """Deanonymize a phone number using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'phone_reverse' not in self.mappings:
            self.mappings['phone_reverse'] = {v: k for k, v in self.mappings['phone'].items()}
        
        # Look up in reverse mapping
        return self.mappings['phone_reverse'].get(value, value)

    def _deanonymize_name(self, value: str) -> str:
        """Deanonymize a name using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'name_reverse' not in self.mappings:
            self.mappings['name_reverse'] = {v: k for k, v in self.mappings['name'].items()}
        
        # Look up in reverse mapping
        return self.mappings['name_reverse'].get(value, value)

    def _deanonymize_address(self, value: str) -> str:
        """Deanonymize an address using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'address_reverse' not in self.mappings:
            self.mappings['address_reverse'] = {v: k for k, v in self.mappings['address'].items()}
        
        # Look up in reverse mapping
        return self.mappings['address_reverse'].get(value, value)

    def _deanonymize_ip(self, value: str) -> str:
        """Deanonymize an IP address using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'ip_reverse' not in self.mappings:
            self.mappings['ip_reverse'] = {v: k for k, v in self.mappings['ip'].items()}
        
        # Look up in reverse mapping
        return self.mappings['ip_reverse'].get(value, value)

    def _deanonymize_datetime(self, value: Any) -> Any:
        """Deanonymize a datetime value by applying the reverse of the consistent shift."""
        try:
            # Parse to datetime if string
            if isinstance(value, str):
                dt = pd.to_datetime(value)
                # Preserve the original format
                original_format = self._detect_datetime_format(value)
            else:
                dt = pd.to_datetime(value)
                original_format = None
            
            # Apply reverse shift (in seconds)
            shifted = dt - pd.Timedelta(seconds=self.mappings['timestamp_shift'])
            
            # Return in original format if detected
            if original_format:
                return shifted.strftime(original_format)
            
            # Otherwise return in same type as input
            if isinstance(value, str):
                return str(shifted)
            return shifted
            
        except:
            # Fall back to string deanonymization if parsing fails
            return self._deanonymize_string(str(value))

    def _deanonymize_boolean(self, value: bool) -> bool:
        """Deanonymize a boolean value."""
        val_str = str(value)
        
        # Create reverse mapping if not already created
        if 'boolean_reverse' not in self.mappings:
            self.mappings['boolean_reverse'] = {v: k for k, v in self.mappings['boolean'].items()}
        
        # Look up in reverse mapping
        result = self.mappings['boolean_reverse'].get(val_str, val_str)
        
        # Convert back to boolean if necessary
        if result == 'True':
            return True
        elif result == 'False':
            return False
        else:
            return value

    def _deanonymize_integer(self, value: int) -> int:
        """Deanonymize an integer value using the mapping."""
        val_str = str(value)
        
        # Create reverse mapping if not already created
        if 'numeric_reverse' not in self.mappings:
            self.mappings['numeric_reverse'] = {v: k for k, v in self.mappings['numeric'].items()}
        
        # Look up in reverse mapping
        result = self.mappings['numeric_reverse'].get(val_str, val_str)
        
        # Convert back to integer
        try:
            return int(result)
        except:
            return value

    def _deanonymize_float(self, value: float) -> float:
        """Deanonymize a float value using the mapping."""
        val_str = str(value)
        
        # Create reverse mapping if not already created
        if 'numeric_reverse' not in self.mappings:
            self.mappings['numeric_reverse'] = {v: k for k, v in self.mappings['numeric'].items()}
        
        # Look up in reverse mapping
        result = self.mappings['numeric_reverse'].get(val_str, val_str)
        
        # Convert back to float
        try:
            return float(result)
        except:
            return value

    def _deanonymize_string(self, value: str) -> str:
        """Deanonymize a general string using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'string_reverse' not in self.mappings:
            self.mappings['string_reverse'] = {v: k for k, v in self.mappings['string'].items()}
        
        # Look up in reverse mapping
        return self.mappings['string_reverse'].get(value, value)

    def _deanonymize_json(self, value: str) -> str:
        """Deanonymize a JSON string using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'string_reverse' not in self.mappings:
            self.mappings['string_reverse'] = {v: k for k, v in self.mappings['string'].items()}
        
        # Look up in reverse mapping
        if value in self.mappings['string_reverse']:
            return self.mappings['string_reverse'][value]
        
        try:
            # Parse JSON
            data = json.loads(value)
            
            # Recursively deanonymize JSON
            deanonymized_data = self._deanonymize_json_object(data)
            
            # Convert back to JSON string with same formatting
            return json.dumps(deanonymized_data, indent=self._detect_json_indent(value))
        except:
            # Fall back to string deanonymization if parsing fails
            return self._deanonymize_string(value)

    def _deanonymize_json_object(self, obj: Any) -> Any:
        """Recursively deanonymize a JSON object."""
        if isinstance(obj, dict):
            return {k: self._deanonymize_json_object(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deanonymize_json_object(item) for item in obj]
        elif isinstance(obj, str):
            return self._deanonymize_string(obj)
        elif isinstance(obj, int):
            return self._deanonymize_integer(obj)
        elif isinstance(obj, float):
            return self._deanonymize_float(obj)
        elif obj is None or isinstance(obj, bool):
            return self._deanonymize_boolean(obj) if isinstance(obj, bool) else obj
        else:
            return self._deanonymize_string(str(obj))
            
    def _deanonymize_binary(self, value: bytes) -> bytes:
        """Deanonymize binary data using the mapping."""
        val_hash = hashlib.md5(value).hexdigest()
        
        # Create reverse mapping if not already created
        if 'binary_reverse' not in self.mappings:
            self.mappings['binary_reverse'] = {hashlib.md5(v).hexdigest(): k for k, v in self.mappings['binary'].items()}
        
        # Look up in reverse mapping
        if val_hash in self.mappings['binary_reverse']:
            return self.mappings['binary'][self.mappings['binary_reverse'][val_hash]]
        
        return value
        
    def _deanonymize_geography(self, value: str) -> str:
        """Deanonymize geographic coordinates using the mapping."""
        if not isinstance(value, str):
            value = str(value)
        
        # Create reverse mapping if not already created
        if 'geography_reverse' not in self.mappings:
            self.mappings['geography_reverse'] = {v: k for k, v in self.mappings['geography'].items()}
        
        # Look up in reverse mapping
        return self.mappings['geography_reverse'].get(value, value)

    def _detect_json_indent(self, json_str: str) -> Optional[int]:
        """Detect indentation in a JSON string."""
        # Default to 2 spaces if indentation can't be detected
        indent = 2
        
        lines = json_str.split("\n")
        if len(lines) > 1:
            for line in lines[1:]:  # Skip first line
                if line.strip() and line.startswith(" "):
                    # Count leading spaces
                    indent = len(line) - len(line.lstrip(" "))
                    break
        
        return indent

    def _anonymize_binary(self, value: bytes) -> bytes:
        """Anonymize binary data while preserving length."""
        # Check if already in mapping
        val_hash = hashlib.md5(value).hexdigest()
        if val_hash in self.mappings['binary']:
            return self.mappings['binary'][val_hash]
        
        # Generate random bytes of same length
        anonymized = bytes(random.getrandbits(8) for _ in range(len(value)))
        
        # Store in mapping
        self.mappings['binary'][val_hash] = anonymized
        
        return anonymized
        
    # CSV file utility functions
    def anonymize_csv(self, input_file: str, output_file: str, 
                      detect_types: bool = True, column_types: Optional[Dict[str, str]] = None,
                      save_mapping: bool = True, mapping_file: Optional[str] = None) -> None:
        """
        Anonymize a CSV file.
        
        Args:
            input_file: Path to input CSV file
            output_file: Path to output anonymized CSV file
            detect_types: Whether to auto-detect column types
            column_types: Optional dictionary mapping column names to types
            save_mapping: Whether to save the mapping file
            mapping_file: Path to save mapping file (default: derived from output_file)
        """
        try:
            # Read CSV
            df = pd.read_csv(input_file)
            
            # Detect column types if requested
            if detect_types:
                detected_types = self._detect_column_types(df)
                # Merge with provided types if any
                if column_types:
                    detected_types.update(column_types)
                column_types = detected_types
            
            # Anonymize
            anonymized_df = self.anonymize_dataframe(df, column_types)
            
            # Save anonymized CSV
            anonymized_df.to_csv(output_file, index=False)
            
            # Save mapping if requested
            if save_mapping:
                if mapping_file is None:
                    # Derive mapping file name from output file
                    mapping_file = f"{os.path.splitext(output_file)[0]}_mapping.pkl"
                
                self.save_mappings(mapping_file)
            
            print(f"Anonymized data saved to {output_file}")
            if save_mapping:
                print(f"Mapping saved to {mapping_file}")
        
        except Exception as e:
            print(f"Error anonymizing CSV: {e}")

    def deanonymize_csv(self, input_file: str, output_file: str, 
                       mapping_file: str, column_types: Optional[Dict[str, str]] = None) -> None:
        """
        Deanonymize a CSV file using a mapping file.
        
        Args:
            input_file: Path to anonymized CSV file
            output_file: Path to output deanonymized CSV file
            mapping_file: Path to mapping file
            column_types: Optional dictionary mapping column names to types
        """
        try:
            # Load mappings
            with open(mapping_file, 'rb') as f:
                self.mappings = pickle.load(f)
            
            # Read CSV
            df = pd.read_csv(input_file)
            
            # Deanonymize
            deanonymized_df = self.deanonymize_dataframe(df, column_types)
            
            # Save deanonymized CSV
            deanonymized_df.to_csv(output_file, index=False)
            
            print(f"Deanonymized data saved to {output_file}")
        
        except Exception as e:
            print(f"Error deanonymizing CSV: {e}")

    def batch_anonymize_csvs(self, input_dir: str, output_dir: str, 
                             file_pattern: str = "*.csv",
                             detect_types: bool = True, 
                             column_types: Optional[Dict[str, Dict[str, str]]] = None,
                             save_mapping: bool = True, 
                             mapping_file: Optional[str] = None) -> None:
        """
        Anonymize multiple CSV files in a directory.
        
        Args:
            input_dir: Directory containing input CSV files
            output_dir: Directory to save anonymized CSV files
            file_pattern: Pattern to match CSV files (default: "*.csv")
            detect_types: Whether to auto-detect column types
            column_types: Optional dictionary mapping filenames to column type dictionaries
            save_mapping: Whether to save the mapping file
            mapping_file: Path to save mapping file (default: derived from output_dir)
        """
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get list of CSV files
        csv_files = glob.glob(os.path.join(input_dir, file_pattern))
        
        if not csv_files:
            print(f"No files matching {file_pattern} found in {input_dir}")
            return
        
        # Process each file
        for input_file in csv_files:
            filename = os.path.basename(input_file)
            output_file = os.path.join(output_dir, filename)
            
            # Get column types for this file if provided
            file_column_types = None
            if column_types and filename in column_types:
                file_column_types = column_types[filename]
            
            # Anonymize
            self.anonymize_csv(
                input_file=input_file,
                output_file=output_file,
                detect_types=detect_types,
                column_types=file_column_types,
                save_mapping=False  # Don't save mapping for each file
            )
        
        # Save final mapping if requested
        if save_mapping:
            if mapping_file is None:
                # Derive mapping file name from output directory
                mapping_file = os.path.join(output_dir, "anonymization_mapping.pkl")
            
            self.save_mappings(mapping_file)
            print(f"Combined mapping for all files saved to {mapping_file}")

    def batch_deanonymize_csvs(self, input_dir: str, output_dir: str, 
                              mapping_file: str,
                              file_pattern: str = "*.csv",
                              column_types: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        """
        Deanonymize multiple CSV files in a directory.
        
        Args:
            input_dir: Directory containing anonymized CSV files
            output_dir: Directory to save deanonymized CSV files
            mapping_file: Path to mapping file
            file_pattern: Pattern to match CSV files (default: "*.csv")
            column_types: Optional dictionary mapping filenames to column type dictionaries
        """
        # Load mappings
        with open(mapping_file, 'rb') as f:
            self.mappings = pickle.load(f)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get list of CSV files
        csv_files = glob.glob(os.path.join(input_dir, file_pattern))
        
        if not csv_files:
            print(f"No files matching {file_pattern} found in {input_dir}")
            return
        
        # Process each file
        for input_file in csv_files:
            filename = os.path.basename(input_file)
            output_file = os.path.join(output_dir, filename)
            
            # Get column types for this file if provided
            file_column_types = None
            if column_types and filename in column_types:
                file_column_types = column_types[filename]
            
            # Deanonymize
            self.deanonymize_csv(
                input_file=input_file,
                output_file=output_file,
                mapping_file=mapping_file,  # Use the same mapping file for all
                column_types=file_column_types
            )
            
# Command-line interface
def main():
    """Command-line interface for data anonymization."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Data Anonymization Tool')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Anonymize CSV command
    anon_parser = subparsers.add_parser('anonymize', help='Anonymize a CSV file')
    anon_parser.add_argument('input', help='Input CSV file')
    anon_parser.add_argument('output', help='Output anonymized CSV file')
    anon_parser.add_argument('--mapping', help='Path to save mapping file')
    anon_parser.add_argument('--no-detect-types', action='store_false', dest='detect_types',
                            help='Disable automatic column type detection')
    anon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    anon_parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    
    # Deanonymize CSV command
    deanon_parser = subparsers.add_parser('deanonymize', help='Deanonymize a CSV file')
    deanon_parser.add_argument('input', help='Input anonymized CSV file')
    deanon_parser.add_argument('output', help='Output deanonymized CSV file')
    deanon_parser.add_argument('--mapping', required=True, help='Path to mapping file')
    deanon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    
    # Batch anonymize command
    batch_anon_parser = subparsers.add_parser('batch-anonymize', help='Anonymize multiple CSV files')
    batch_anon_parser.add_argument('input_dir', help='Input directory containing CSV files')
    batch_anon_parser.add_argument('output_dir', help='Output directory for anonymized files')
    batch_anon_parser.add_argument('--pattern', default='*.csv', help='File pattern to match (default: *.csv)')
    batch_anon_parser.add_argument('--mapping', help='Path to save mapping file')
    batch_anon_parser.add_argument('--no-detect-types', action='store_false', dest='detect_types',
                                help='Disable automatic column type detection')
    batch_anon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    batch_anon_parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    
    # Batch deanonymize command
    batch_deanon_parser = subparsers.add_parser('batch-deanonymize', help='Deanonymize multiple CSV files')
    batch_deanon_parser.add_argument('input_dir', help='Input directory containing anonymized CSV files')
    batch_deanon_parser.add_argument('output_dir', help='Output directory for deanonymized files')
    batch_deanon_parser.add_argument('--pattern', default='*.csv', help='File pattern to match (default: *.csv)')
    batch_deanon_parser.add_argument('--mapping', required=True, help='Path to mapping file')
    batch_deanon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Load column types from JSON file if provided
    column_types = None
    if hasattr(args, 'column_types') and args.column_types:
        try:
            with open(args.column_types, 'r') as f:
                column_types = json.load(f)
        except Exception as e:
            print(f"Error loading column types file: {e}")
            return
    
    # Initialize anonymizer
    seed = args.seed if hasattr(args, 'seed') else None
    anonymizer = DataAnonymizer(seed=seed)
    
    # Execute appropriate command
    if args.command == 'anonymize':
        anonymizer.anonymize_csv(
            input_file=args.input,
            output_file=args.output,
            detect_types=args.detect_types,
            column_types=column_types,
            mapping_file=args.mapping
        )
    
    elif args.command == 'deanonymize':
        anonymizer.deanonymize_csv(
            input_file=args.input,
            output_file=args.output,
            mapping_file=args.mapping,
            column_types=column_types
        )
    
    elif args.command == 'batch-anonymize':
        anonymizer.batch_anonymize_csvs(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            file_pattern=args.pattern,
            detect_types=args.detect_types,
            column_types=column_types,
            mapping_file=args.mapping
        )
    
    elif args.command == 'batch-deanonymize':
        anonymizer.batch_deanonymize_csvs(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            file_pattern=args.pattern,
            mapping_file=args.mapping,
            column_types=column_types
        )


if __name__ == "__main__":
    main()

    def _anonymize_geography(self, value: str) -> str:
        """Anonymize geographic coordinates while preserving format."""
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings['geography']:
            return self.mappings['geography'][value]
        
        # Try to parse as WKT (Well-Known Text) format
        try:
            # Simple WKT point format: "POINT(longitude latitude)"
            if value.startswith("POINT"):
                match = re.search(r"POINT\s*\(\s*([+-]?\d+(\.\d+)?)\s+([+-]?\d+(\.\d+)?)\s*\)", value)
                if match:
                    lon = float(match.group(1))
                    lat = float(match.group(3))
                    
                    # Apply small random shift (±0.01 degrees, about 1km)
                    new_lon = lon + random.uniform(-0.01, 0.01)
                    new_lat = lat + random.uniform(-0.01, 0.01)
                    
                    # Keep in valid range
                    new_lon = max(-180, min(180, new_lon))
                    new_lat = max(-90, min(90, new_lat))
                    
                    # Format with same precision
                    lon_precision = len(match.group(1).split('.')[-1]) if '.' in match.group(1) else 0
                    lat_precision = len(match.group(3).split('.')[-1]) if '.' in match.group(3) else 0
                    
                    anonymized = f"POINT({new_lon:.{lon_precision}f} {new_lat:.{lat_precision}f})"
                    
                    # Store in mapping
                    self.mappings['geography'][value] = anonymized
                    
                    return anonymized
            
            # If not a recognized format, treat as string
            return self._anonymize_string(value)
        
        except Exception:
            # Fall back to string anonymization if parsing fails
            return self._anonymize_string(value)