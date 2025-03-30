"""
Data transformation module for anonymizing and deanonymizing data.

This module contains functions for transforming data of various types
while preserving their format and character count.
"""

import re
import uuid
import random
import string
import hashlib
import json
import datetime
import pandas as pd
from typing import Dict, Any, List, Union, Optional


def anonymize_uuid(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize a UUID while preserving format.
    
    Args:
        value: The UUID to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized UUID
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['uuid']:
        return mappings['uuid'][value]
    
    # Generate a new UUID
    anonymized = str(uuid.uuid4())
    
    # Store in mapping
    mappings['uuid'][value] = anonymized
    
    return anonymized


def anonymize_email(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize an email address while preserving format.
    
    Args:
        value: The email address to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized email address
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['email']:
        return mappings['email'][value]
    
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
    mappings['email'][value] = anonymized
    
    return anonymized


def anonymize_phone(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize a phone number while preserving format.
    
    Args:
        value: The phone number to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized phone number
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['phone']:
        return mappings['phone'][value]
    
    # Keep the same formatting but replace digits
    anonymized = re.sub(r'\d', lambda _: str(random.randint(0, 9)), value)
    
    # Store in mapping
    mappings['phone'][value] = anonymized
    
    return anonymized


def anonymize_name(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize a name while preserving length and capitalization.
    
    Args:
        value: The name to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized name
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['name']:
        return mappings['name'][value]
    
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
    mappings['name'][value] = anonymized
    
    return anonymized


def anonymize_address(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize an address while preserving format and length.
    
    Args:
        value: The address to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized address
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['address']:
        return mappings['address'][value]
    
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
    mappings['address'][value] = anonymized
    
    return anonymized


def anonymize_ip(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize an IP address while preserving format (IPv4 or IPv6).
    
    Args:
        value: The IP address to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized IP address
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['ip']:
        return mappings['ip'][value]
    
    # Check if IPv4 or IPv6
    if '.' in value:  # IPv4
        octets = value.split('.')
        anonymized = '.'.join(str(random.randint(0, 255)) for _ in octets)
    else:  # IPv6
        segments = value.split(':')
        anonymized = ':'.join(format(random.randint(0, 65535), 'x').zfill(4) for _ in segments)
    
    # Store in mapping
    mappings['ip'][value] = anonymized
    
    return anonymized


def _detect_datetime_format(date_string: str) -> str:
    """
    Attempt to detect the format of a datetime string.
    
    Args:
        date_string: The datetime string to analyze
        
    Returns:
        The detected datetime format string
    """
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


def anonymize_datetime(value: Any, mappings: Dict[str, Dict[str, Any]]) -> Any:
    """
    Anonymize a datetime value by applying a consistent shift.
    
    Args:
        value: The datetime value to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized datetime value
    """
    try:
        # Parse to datetime if string
        if isinstance(value, str):
            dt = pd.to_datetime(value)
            # Preserve the original format
            original_format = _detect_datetime_format(value)
        else:
            dt = pd.to_datetime(value)
            original_format = None
        
        # Apply shift (in seconds)
        shifted = dt + pd.Timedelta(seconds=mappings['timestamp_shift'])
        
        # Return in original format if detected
        if original_format:
            return shifted.strftime(original_format)
        
        # Otherwise return in same type as input
        if isinstance(value, str):
            return str(shifted)
        return shifted
        
    except:
        # Fall back to string anonymization if parsing fails
        if 'string' not in mappings:
            mappings['string'] = {}
        return anonymize_string(str(value), mappings)


def anonymize_boolean(value: bool, mappings: Dict[str, Dict[str, Any]]) -> bool:
    """
    Anonymize a boolean value.
    
    Args:
        value: The boolean value to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized boolean value (typically unchanged)
    """
    # For consistency in anonymization, we'll randomly flip based on hash
    val_str = str(value)
    
    # Check if already in mapping
    if val_str in mappings['boolean']:
        return mappings['boolean'][val_str]
    
    # We can either keep as is or randomly flip
    # For this implementation, we'll keep as is (not sensitive)
    anonymized = value
    
    # Store in mapping
    mappings['boolean'][val_str] = anonymized
    
    return anonymized


def anonymize_integer(value: int, mappings: Dict[str, Dict[str, Any]]) -> int:
    """
    Anonymize an integer value while preserving magnitude.
    
    Args:
        value: The integer value to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized integer value
    """
    val_str = str(value)
    
    # Check if already in mapping
    if val_str in mappings['numeric']:
        return mappings['numeric'][val_str]
    
    # Keep sign and approximate magnitude, but change the value
    sign = -1 if value < 0 else 1
    magnitude = 10 ** (len(str(abs(value))) - 1)
    
    # Generate a random number with same number of digits
    if magnitude > 0:
        anonymized = sign * (random.randint(magnitude, 10 * magnitude - 1))
    else:
        anonymized = 0
    
    # Store in mapping
    mappings['numeric'][val_str] = anonymized
    
    return anonymized


def anonymize_float(value: float, mappings: Dict[str, Dict[str, Any]]) -> float:
    """
    Anonymize a float value while preserving magnitude and precision.
    
    Args:
        value: The float value to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized float value
    """
    val_str = str(value)
    
    # Check if already in mapping
    if val_str in mappings['numeric']:
        return mappings['numeric'][val_str]
    
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
    mappings['numeric'][val_str] = anonymized
    
    return anonymized


def anonymize_numeric(value: Union[int, float], mappings: Dict[str, Dict[str, Any]]) -> Union[int, float]:
    """
    Anonymize a numeric value (integer or float).
    
    Args:
        value: The numeric value to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized numeric value
    """
    if isinstance(value, int):
        return anonymize_integer(value, mappings)
    elif isinstance(value, float):
        return anonymize_float(value, mappings)
    else:
        # Try to convert to numeric
        try:
            float_val = float(value)
            if float_val.is_integer():
                return anonymize_integer(int(float_val), mappings)
            else:
                return anonymize_float(float_val, mappings)
        except:
            # Fall back to string anonymization
            return anonymize_string(str(value), mappings)


def anonymize_string(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize a general string while preserving length and character types.
    
    Args:
        value: The string value to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized string value
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['string']:
        return mappings['string'][value]
    
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
    mappings['string'][value] = anonymized
    
    return anonymized


def _detect_json_indent(json_str: str) -> Optional[int]:
    """
    Detect indentation in a JSON string.
    
    Args:
        json_str: JSON string to analyze
        
    Returns:
        Detected indentation level
    """
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


def _anonymize_json_object(obj: Any, mappings: Dict[str, Dict[str, Any]]) -> Any:
    """
    Recursively anonymize a JSON object.
    
    Args:
        obj: The JSON object to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized JSON object
    """
    if isinstance(obj, dict):
        return {k: _anonymize_json_object(v, mappings) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_anonymize_json_object(item, mappings) for item in obj]
    elif isinstance(obj, str):
        return anonymize_string(obj, mappings)
    elif isinstance(obj, int):
        return anonymize_integer(obj, mappings)
    elif isinstance(obj, float):
        return anonymize_float(obj, mappings)
    elif obj is None or isinstance(obj, bool):
        return obj if obj is None else anonymize_boolean(obj, mappings)
    else:
        return anonymize_string(str(obj), mappings)


def anonymize_json(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize a JSON string while preserving structure.
    
    Args:
        value: The JSON string to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized JSON string
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['string']:
        return mappings['string'][value]
    
    try:
        # Parse JSON
        data = json.loads(value)
        
        # Recursively anonymize JSON
        anonymized_data = _anonymize_json_object(data, mappings)
        
        # Convert back to JSON string with same formatting
        anonymized = json.dumps(anonymized_data, indent=_detect_json_indent(value))
        
        # Store in mapping
        mappings['string'][value] = anonymized
        
        return anonymized
    except:
        # Fall back to string anonymization if parsing fails
        return anonymize_string(value, mappings)


def anonymize_binary(value: bytes, mappings: Dict[str, Dict[str, Any]]) -> bytes:
    """
    Anonymize binary data while preserving length.
    
    Args:
        value: The binary data to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized binary data
    """
    # Check if already in mapping
    val_hash = hashlib.md5(value).hexdigest()
    if val_hash in mappings['binary']:
        return mappings['binary'][val_hash]
    
    # Generate random bytes of same length
    anonymized = bytes(random.getrandbits(8) for _ in range(len(value)))
    
    # Store in mapping
    mappings['binary'][val_hash] = anonymized
    
    return anonymized


def anonymize_geography(value: str, mappings: Dict[str, Dict[str, Any]]) -> str:
    """
    Anonymize geographic coordinates while preserving format.
    
    Args:
        value: The geographic coordinates to anonymize
        mappings: Dictionary containing anonymization mappings
        
    Returns:
        Anonymized geographic coordinates
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Check if already in mapping
    if value in mappings['geography']:
        return mappings['geography'][value]
    
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
                mappings['geography'][value] = anonymized
                
                return anonymized
        
        # If not a recognized format, treat as string
        return anonymize_string(value, mappings)
    
    except Exception:
        # Fall back to string anonymization if parsing fails
        return anonymize_string(value, mappings)