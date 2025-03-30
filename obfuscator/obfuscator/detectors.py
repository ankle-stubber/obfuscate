"""
Data type detection module for automatic detection of column data types.
"""

import re
import json
import pandas as pd
from typing import Dict, Any, List


class DataTypeDetector:
    """
    Class for detecting data types in DataFrames and Series.
    
    Provides methods to automatically identify the type of data in columns
    based on column names and content patterns.
    """
    
    @staticmethod
    def detect_column_types(df: pd.DataFrame) -> Dict[str, str]:
        """
        Detect the types of each column in the DataFrame.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Dictionary mapping column names to their detected types
        """
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
                if DataTypeDetector._is_uuid(df[col]):
                    column_types[col] = 'uuid'
                    continue
            
            # Email detection
            if any(term in col_lower for term in ['email', 'e-mail', 'mail']):
                if DataTypeDetector._is_email(df[col]):
                    column_types[col] = 'email'
                    continue
            
            # Phone detection
            if any(term in col_lower for term in ['phone', 'mobile', 'cell', 'tel']):
                if DataTypeDetector._is_phone(df[col]):
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
                if DataTypeDetector._is_ip(df[col]):
                    column_types[col] = 'ip'
                    continue
            
            # Date/Time detection
            if any(term in col_lower for term in ['date', 'time', 'timestamp']):
                if DataTypeDetector._is_datetime(df[col]):
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
            elif DataTypeDetector._is_json(df[col]):
                column_types[col] = 'json'
            elif pd.api.types.is_object_dtype(df[col]):
                # Further check for specific string formats
                if DataTypeDetector._is_uuid(df[col]):
                    column_types[col] = 'uuid'
                elif DataTypeDetector._is_email(df[col]):
                    column_types[col] = 'email'
                elif DataTypeDetector._is_phone(df[col]):
                    column_types[col] = 'phone'
                elif DataTypeDetector._is_ip(df[col]):
                    column_types[col] = 'ip'
                elif DataTypeDetector._is_datetime(df[col]):
                    column_types[col] = 'datetime'
                else:
                    column_types[col] = 'string'
            else:
                # Default to string for any other type
                column_types[col] = 'string'
        
        return column_types

    @staticmethod
    def _is_uuid(series: pd.Series) -> bool:
        """Check if a series contains UUID values."""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        # Check a sample of non-null values
        sample = series.dropna().head(10)
        return all(bool(re.match(pattern, str(x), re.IGNORECASE)) for x in sample)

    @staticmethod
    def _is_email(series: pd.Series) -> bool:
        """Check if a series contains email addresses."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        # Check a sample of non-null values
        sample = series.dropna().head(10)
        return all(bool(re.match(pattern, str(x))) for x in sample)

    @staticmethod
    def _is_phone(series: pd.Series) -> bool:
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

    @staticmethod
    def _is_ip(series: pd.Series) -> bool:
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

    @staticmethod
    def _is_datetime(series: pd.Series) -> bool:
        """Check if a series contains datetime values."""
        try:
            pd.to_datetime(series.dropna().head(10))
            return True
        except:
            return False

    @staticmethod
    def _is_json(series: pd.Series) -> bool:
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