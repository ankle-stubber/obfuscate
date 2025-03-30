"""
Test module for the DataAnonymizer class.
"""

import os
import unittest
import pandas as pd
import tempfile
from obfuscator.obfuscator import DataAnonymizer


class TestDataAnonymizer(unittest.TestCase):
    """Test cases for the DataAnonymizer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.anonymizer = DataAnonymizer(seed=42)
        
        # Create a test DataFrame with various data types
        self.test_df = pd.DataFrame({
            'uuid_col': ['123e4567-e89b-12d3-a456-426614174000', 
                         '123e4567-e89b-12d3-a456-426614174001'],
            'email_col': ['john.doe@example.com', 'jane.smith@example.com'],
            'phone_col': ['(123) 456-7890', '123-456-7891'],
            'name_col': ['John Doe', 'Jane Smith'],
            'address_col': ['123 Main St, City, 12345', '456 Oak Ave, Town, 67890'],
            'ip_col': ['192.168.1.1', '10.0.0.1'],
            'datetime_col': ['2023-01-01', '2023-01-02'],
            'boolean_col': [True, False],
            'integer_col': [123, 456],
            'float_col': [123.45, 678.90],
            'json_col': ['{"key": "value"}', '{"name": "test"}'],
            'string_col': ['Hello, World!', 'Testing 123']
        })
        
        # Create temp files for CSV tests
        self.temp_dir = tempfile.TemporaryDirectory()
        self.input_csv = os.path.join(self.temp_dir.name, 'input.csv')
        self.output_csv = os.path.join(self.temp_dir.name, 'output.csv')
        self.mapping_file = os.path.join(self.temp_dir.name, 'mapping.pkl')
        self.restore_csv = os.path.join(self.temp_dir.name, 'restore.csv')
        
        # Save test DataFrame to CSV
        self.test_df.to_csv(self.input_csv, index=False)

    def tearDown(self):
        """Tear down test fixtures."""
        self.temp_dir.cleanup()

    def test_anonymize_dataframe(self):
        """Test anonymizing a DataFrame."""
        # Anonymize the DataFrame
        anonymized_df = self.anonymizer.anonymize_dataframe(self.test_df)
        
        # Check that the anonymized DataFrame has the same shape
        self.assertEqual(self.test_df.shape, anonymized_df.shape)
        
        # Check that sensitive columns were actually anonymized
        for col in ['email_col', 'phone_col', 'name_col', 'address_col', 'string_col']:
            # Values should be different
            self.assertFalse((self.test_df[col] == anonymized_df[col]).all())
            
            # But lengths should be the same
            self.assertEqual(
                self.test_df[col].str.len().tolist(),
                anonymized_df[col].str.len().tolist()
            )
            
    def test_deanonymize_dataframe(self):
        """Test deanonymizing a DataFrame."""
        # Anonymize the DataFrame
        anonymized_df = self.anonymizer.anonymize_dataframe(self.test_df)
        
        # Save the mappings
        self.anonymizer.save_mappings(self.mapping_file)
        
        # Create a new anonymizer with the same mappings
        deanonymizer = DataAnonymizer(mapping_file=self.mapping_file)
        
        # Deanonymize the DataFrame
        restored_df = deanonymizer.deanonymize_dataframe(anonymized_df)
        
        # Check that the restored DataFrame equals the original
        pd.testing.assert_frame_equal(self.test_df, restored_df)

    def test_csv_anonymization(self):
        """Test anonymizing and deanonymizing a CSV file."""
        # Anonymize the CSV
        self.anonymizer.anonymize_csv(
            input_file=self.input_csv,
            output_file=self.output_csv,
            mapping_file=self.mapping_file
        )
        
        # Check that the output CSV exists
        self.assertTrue(os.path.exists(self.output_csv))
        
        # Check that the mapping file exists
        self.assertTrue(os.path.exists(self.mapping_file))
        
        # Read the anonymized CSV
        anonymized_df = pd.read_csv(self.output_csv)
        
        # Create a new anonymizer with the mappings
        deanonymizer = DataAnonymizer(mapping_file=self.mapping_file)
        
        # Deanonymize the CSV
        deanonymizer.deanonymize_csv(
            input_file=self.output_csv,
            output_file=self.restore_csv,
            mapping_file=self.mapping_file
        )
        
        # Check that the restored CSV exists
        self.assertTrue(os.path.exists(self.restore_csv))
        
        # Read the restored CSV
        restored_df = pd.read_csv(self.restore_csv)
        
        # Check that the restored DataFrame equals the original
        original_df = pd.read_csv(self.input_csv)
        pd.testing.assert_frame_equal(original_df, restored_df)


if __name__ == '__main__':
    unittest.main()