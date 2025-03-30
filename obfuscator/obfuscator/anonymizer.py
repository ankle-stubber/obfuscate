"""
Core anonymization class that provides the main functionality.
"""

import os
import glob
import pickle
import random
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Tuple, Union, Optional

from .detectors import DataTypeDetector
from .transformers import (
    anonymize_uuid,
    anonymize_email,
    anonymize_phone,
    anonymize_name,
    anonymize_address,
    anonymize_ip,
    anonymize_datetime,
    anonymize_boolean,
    anonymize_integer,
    anonymize_float,
    anonymize_string,
    anonymize_json,
    anonymize_binary,
    anonymize_geography
)


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
        """
        Initialize the anonymizer with optional seed and existing mappings.
        
        Args:
            seed: Optional random seed for reproducibility
            mapping_file: Optional path to load existing mappings
            timestamp_shift: Optional fixed timestamp shift in seconds
        """
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
        """
        Load mappings from a file.
        
        Args:
            mapping_file: Path to the mapping file
            
        Returns:
            Dictionary containing loaded mappings
        """
        try:
            with open(mapping_file, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error loading mapping file: {e}")
            return {}
    
    def save_mappings(self, mapping_file: str) -> None:
        """
        Save mappings to a file.
        
        Args:
            mapping_file: Path to save the mapping file
        """
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
            column_types = DataTypeDetector.detect_column_types(df)
        
        # Apply appropriate anonymization function to each column
        for col in df.columns:
            col_type = column_types.get(col, 'string')
            anon_df[col] = self._anonymize_column(df[col], col_type)
        
        return anon_df
            
    def _anonymize_column(self, series: pd.Series, col_type: str) -> pd.Series:
        """
        Apply appropriate anonymization based on column type.
        
        Args:
            series: Input pandas Series
            col_type: The detected or specified column type
            
        Returns:
            Anonymized pandas Series
        """
        # Handle null values
        if series.isna().all() or col_type == 'null':
            return series
        
        # Make a copy to avoid modifying the original
        result = series.copy()
        
        # Choose the appropriate anonymization function based on column type
        if col_type == 'uuid':
            result = result.apply(lambda x: anonymize_uuid(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'email':
            result = result.apply(lambda x: anonymize_email(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'phone':
            result = result.apply(lambda x: anonymize_phone(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'name':
            result = result.apply(lambda x: anonymize_name(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'address':
            result = result.apply(lambda x: anonymize_address(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'ip':
            result = result.apply(lambda x: anonymize_ip(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'datetime':
            result = result.apply(lambda x: anonymize_datetime(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'boolean':
            result = result.apply(lambda x: anonymize_boolean(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'integer':
            result = result.apply(lambda x: anonymize_integer(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'float':
            result = result.apply(lambda x: anonymize_float(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'json':
            result = result.apply(lambda x: anonymize_json(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'geography':
            result = result.apply(lambda x: anonymize_geography(x, self.mappings) if not pd.isna(x) else x)
        elif col_type == 'binary':
            result = result.apply(lambda x: anonymize_binary(x, self.mappings) if not pd.isna(x) else x)
        else:  # Default to string
            result = result.apply(lambda x: anonymize_string(x, self.mappings) if not pd.isna(x) else x)
        
        return result
        
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
            original_column_types = DataTypeDetector.detect_column_types(df)
        
        # Create reverse mappings if they don't exist
        self._create_reverse_mappings()
        
        # Apply appropriate deanonymization function to each column
        for col in df.columns:
            col_type = original_column_types.get(col, 'string')
            deanon_df[col] = self._deanonymize_column(df[col], col_type)
        
        return deanon_df

    def _create_reverse_mappings(self):
        """Create reverse mappings for deanonymization."""
        for mapping_type in self.mappings:
            if mapping_type != 'timestamp_shift' and isinstance(self.mappings[mapping_type], dict):
                if f"{mapping_type}_reverse" not in self.mappings:
                    if mapping_type == 'binary':
                        # Special handling for binary data
                        import hashlib
                        self.mappings[f"{mapping_type}_reverse"] = {
                            hashlib.md5(v).hexdigest(): k for k, v in self.mappings[mapping_type].items()
                        }
                    else:
                        # Regular mapping
                        self.mappings[f"{mapping_type}_reverse"] = {
                            v: k for k, v in self.mappings[mapping_type].items()
                        }

    def _deanonymize_column(self, series: pd.Series, col_type: str) -> pd.Series:
        """
        Apply appropriate deanonymization based on column type.
        
        Args:
            series: Input anonymized pandas Series
            col_type: The detected or specified column type
            
        Returns:
            Deanonymized pandas Series
        """
        # Handle null values
        if series.isna().all() or col_type == 'null':
            return series
        
        # Make a copy to avoid modifying the original
        result = series.copy()
        
        # Ensure reverse mappings exist
        self._create_reverse_mappings()
        
        # Choose the appropriate deanonymization function based on column type
        if col_type == 'uuid':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'uuid') if not pd.isna(x) else x)
        elif col_type == 'email':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'email') if not pd.isna(x) else x)
        elif col_type == 'phone':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'phone') if not pd.isna(x) else x)
        elif col_type == 'name':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'name') if not pd.isna(x) else x)
        elif col_type == 'address':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'address') if not pd.isna(x) else x)
        elif col_type == 'ip':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'ip') if not pd.isna(x) else x)
        elif col_type == 'datetime':
            result = result.apply(lambda x: self._deanonymize_datetime(x) if not pd.isna(x) else x)
        elif col_type == 'boolean':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'boolean') if not pd.isna(x) else x)
        elif col_type == 'integer' or col_type == 'float':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'numeric') if not pd.isna(x) else x)
        elif col_type == 'json':
            result = result.apply(lambda x: self._deanonymize_json(x) if not pd.isna(x) else x)
        elif col_type == 'geography':
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'geography') if not pd.isna(x) else x)
        elif col_type == 'binary':
            result = result.apply(lambda x: self._deanonymize_binary(x) if not pd.isna(x) else x)
        else:  # Default to string
            result = result.apply(lambda x: self._deanonymize_mapping(x, 'string') if not pd.isna(x) else x)
        
        return result

    def _deanonymize_mapping(self, value: Any, mapping_type: str) -> Any:
        """
        Generic deanonymization using reverse mapping lookup.
        
        Args:
            value: The value to deanonymize
            mapping_type: The type of mapping to use
            
        Returns:
            Deanonymized value
        """
        val_str = str(value)
        reverse_map = f"{mapping_type}_reverse"
        
        # Look up in reverse mapping
        if reverse_map in self.mappings and val_str in self.mappings[reverse_map]:
            result = self.mappings[reverse_map][val_str]
            
            # Try to convert to original type if numeric
            if mapping_type == 'numeric':
                try:
                    if '.' in result:
                        return float(result)
                    else:
                        return int(result)
                except:
                    pass
            elif mapping_type == 'boolean':
                if result == 'True':
                    return True
                elif result == 'False':
                    return False
            
            return result
        
        # Return original if not found in mapping
        return value

    def _deanonymize_datetime(self, value: Any) -> Any:
        """
        Deanonymize a datetime value by applying the reverse of the consistent shift.
        
        Args:
            value: The datetime value to deanonymize
            
        Returns:
            Deanonymized datetime value
        """
        try:
            # Parse to datetime if string
            if isinstance(value, str):
                dt = pd.to_datetime(value)
                # Preserve the original format
                from .transformers import _detect_datetime_format
                original_format = _detect_datetime_format(value)
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
            return self._deanonymize_mapping(str(value), 'string')

    def _deanonymize_json(self, value: str) -> str:
        """
        Deanonymize a JSON string using the mapping.
        
        Args:
            value: The JSON string to deanonymize
            
        Returns:
            Deanonymized JSON string
        """
        import json
        
        if not isinstance(value, str):
            value = str(value)
        
        # Check if already in mapping
        if value in self.mappings.get('string_reverse', {}):
            return self.mappings['string_reverse'][value]
        
        try:
            # Parse JSON
            data = json.loads(value)
            
            # Recursively deanonymize JSON
            deanonymized_data = self._deanonymize_json_object(data)
            
            # Convert back to JSON string with same formatting
            from .transformers import _detect_json_indent
            return json.dumps(deanonymized_data, indent=_detect_json_indent(value))
        except:
            # Fall back to string deanonymization if parsing fails
            return self._deanonymize_mapping(value, 'string')

    def _deanonymize_json_object(self, obj: Any) -> Any:
        """
        Recursively deanonymize a JSON object.
        
        Args:
            obj: The JSON object to deanonymize
            
        Returns:
            Deanonymized JSON object
        """
        if isinstance(obj, dict):
            return {k: self._deanonymize_json_object(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deanonymize_json_object(item) for item in obj]
        elif isinstance(obj, str):
            return self._deanonymize_mapping(obj, 'string')
        elif isinstance(obj, int):
            return self._deanonymize_mapping(obj, 'numeric')
        elif isinstance(obj, float):
            return self._deanonymize_mapping(obj, 'numeric')
        elif obj is None or isinstance(obj, bool):
            return self._deanonymize_mapping(obj, 'boolean') if isinstance(obj, bool) else obj
        else:
            return self._deanonymize_mapping(str(obj), 'string')

    def _deanonymize_binary(self, value: bytes) -> bytes:
        """
        Deanonymize binary data using the mapping.
        
        Args:
            value: The binary data to deanonymize
            
        Returns:
            Deanonymized binary data
        """
        import hashlib
        val_hash = hashlib.md5(value).hexdigest()
        
        # Look up in reverse mapping
        if 'binary_reverse' in self.mappings and val_hash in self.mappings['binary_reverse']:
            original_hash = self.mappings['binary_reverse'][val_hash]
            if original_hash in self.mappings['binary']:
                return self.mappings['binary'][original_hash]
        
        return value

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
                detected_types = DataTypeDetector.detect_column_types(df)
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
                if not mapping_file or mapping_file.strip() == '':
                    # Derive mapping file name from output file
                    mapping_file = f"{os.path.splitext(output_file)[0]}_mapping.pkl"
                
                self.save_mappings(mapping_file)
            
            print(f"Anonymized data saved to {output_file}")
            if save_mapping and mapping_file:
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
            if not mapping_file or mapping_file.strip() == '':
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