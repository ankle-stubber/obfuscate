"""
Command-line interface for the Obfuscator data anonymization tool.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, Optional

from .anonymizer import DataAnonymizer


def prompt_for_input(prompt_text: str, required: bool = True) -> str:
    """
    Prompt the user for input with the given text.
    
    Args:
        prompt_text: The text to show in the prompt
        required: Whether the input is required
        
    Returns:
        The user's input
    """
    while True:
        value = input(f"{prompt_text}: ")
        if value or not required:
            return value
        print("This value is required. Please try again.")


def interactive_anonymize(anonymizer: DataAnonymizer):
    """Run interactive anonymize command."""
    input_file = prompt_for_input("Enter the input CSV file path")
    output_file = prompt_for_input("Enter the output CSV file path")
    
    # Create parent directory for output file if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # For mapping file, suggest a default path rather than empty string
    default_mapping_path = f"{os.path.splitext(output_file)[0]}_mapping.pkl"
    mapping_prompt = f"Enter the mapping file path (press Enter for {default_mapping_path})"
    mapping_file = prompt_for_input(mapping_prompt, required=False) or default_mapping_path
    
    detect_types = prompt_for_input("Auto-detect column types? (y/n, default: y)", required=False).lower() != 'n'
    
    # Ask for column types file
    column_types_file = prompt_for_input("Enter column types JSON file path (press Enter to skip)", required=False)
    column_types = None
    if column_types_file:
        try:
            with open(column_types_file, 'r') as f:
                column_types = json.load(f)
        except Exception as e:
            print(f"Error loading column types file: {e}")
            return
    
    # Ask for seed
    seed_str = prompt_for_input("Enter random seed (press Enter to skip)", required=False)
    seed = int(seed_str) if seed_str and seed_str.isdigit() else None
    if seed is not None:
        anonymizer = DataAnonymizer(seed=seed)
    
    print(f"\nAnonymizing {input_file} to {output_file}...")
    anonymizer.anonymize_csv(
        input_file=input_file,
        output_file=output_file,
        detect_types=detect_types,
        column_types=column_types,
        mapping_file=mapping_file
    )


def interactive_deanonymize(anonymizer: DataAnonymizer):
    """Run interactive deanonymize command."""
    input_file = prompt_for_input("Enter the input anonymized CSV file path")
    output_file = prompt_for_input("Enter the output restored CSV file path")
    
    # Create parent directory for output file if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Suggest a default mapping file based on the input file path
    default_mapping_path = f"{os.path.splitext(input_file)[0]}_mapping.pkl"
    if os.path.exists(default_mapping_path):
        mapping_prompt = f"Enter the mapping file path (press Enter for {default_mapping_path})"
        mapping_file = prompt_for_input(mapping_prompt, required=False) or default_mapping_path
    else:
        mapping_file = prompt_for_input("Enter the mapping file path")
    
    # Ask for column types file
    column_types_file = prompt_for_input("Enter column types JSON file path (press Enter to skip)", required=False)
    column_types = None
    if column_types_file:
        try:
            with open(column_types_file, 'r') as f:
                column_types = json.load(f)
        except Exception as e:
            print(f"Error loading column types file: {e}")
            return
    
    print(f"\nDeanonymizing {input_file} to {output_file}...")
    anonymizer.deanonymize_csv(
        input_file=input_file,
        output_file=output_file,
        mapping_file=mapping_file,
        column_types=column_types
    )


def interactive_batch_anonymize(anonymizer: DataAnonymizer):
    """Run interactive batch anonymize command."""
    input_dir = prompt_for_input("Enter the input directory containing CSV files")
    output_dir = prompt_for_input("Enter the output directory for anonymized files")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    pattern = prompt_for_input("Enter file pattern to match (default: *.csv)", required=False) or "*.csv"
    
    # For mapping file, suggest a default path rather than empty string
    default_mapping_path = os.path.join(output_dir, "anonymization_mapping.pkl")
    mapping_prompt = f"Enter the mapping file path (press Enter for {default_mapping_path})"
    mapping_file = prompt_for_input(mapping_prompt, required=False) or default_mapping_path
    
    detect_types = prompt_for_input("Auto-detect column types? (y/n, default: y)", required=False).lower() != 'n'
    
    # Ask for column types file
    column_types_file = prompt_for_input("Enter column types JSON file path (press Enter to skip)", required=False)
    column_types = None
    if column_types_file:
        try:
            with open(column_types_file, 'r') as f:
                column_types = json.load(f)
        except Exception as e:
            print(f"Error loading column types file: {e}")
            return
    
    # Ask for seed
    seed_str = prompt_for_input("Enter random seed (press Enter to skip)", required=False)
    seed = int(seed_str) if seed_str and seed_str.isdigit() else None
    if seed is not None:
        anonymizer = DataAnonymizer(seed=seed)
    
    print(f"\nBatch anonymizing files from {input_dir} to {output_dir}...")
    anonymizer.batch_anonymize_csvs(
        input_dir=input_dir,
        output_dir=output_dir,
        file_pattern=pattern,
        detect_types=detect_types,
        column_types=column_types,
        mapping_file=mapping_file
    )


def interactive_batch_deanonymize(anonymizer: DataAnonymizer):
    """Run interactive batch deanonymize command."""
    input_dir = prompt_for_input("Enter the input directory containing anonymized CSV files")
    output_dir = prompt_for_input("Enter the output directory for restored files")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    pattern = prompt_for_input("Enter file pattern to match (default: *.csv)", required=False) or "*.csv"
    
    # Suggest a default mapping file based on the input directory
    default_mapping_path = os.path.join(input_dir, "anonymization_mapping.pkl")
    if os.path.exists(default_mapping_path):
        mapping_prompt = f"Enter the mapping file path (press Enter for {default_mapping_path})"
        mapping_file = prompt_for_input(mapping_prompt, required=False) or default_mapping_path
    else:
        mapping_file = prompt_for_input("Enter the mapping file path")
    
    # Ask for column types file
    column_types_file = prompt_for_input("Enter column types JSON file path (press Enter to skip)", required=False)
    column_types = None
    if column_types_file:
        try:
            with open(column_types_file, 'r') as f:
                column_types = json.load(f)
        except Exception as e:
            print(f"Error loading column types file: {e}")
            return
    
    print(f"\nBatch deanonymizing files from {input_dir} to {output_dir}...")
    anonymizer.batch_deanonymize_csvs(
        input_dir=input_dir,
        output_dir=output_dir,
        file_pattern=pattern,
        mapping_file=mapping_file,
        column_types=column_types
    )


def main():
    """
    Command-line interface for data anonymization.
    
    This function provides the entry point for the CLI tool.
    """
    parser = argparse.ArgumentParser(description='Obfuscator Data Anonymization Tool')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Anonymize CSV command
    anon_parser = subparsers.add_parser('anonymize', help='Anonymize a CSV file')
    anon_parser.add_argument('input', nargs='?', help='Input CSV file')
    anon_parser.add_argument('output', nargs='?', help='Output anonymized CSV file')
    anon_parser.add_argument('--mapping', help='Path to save mapping file')
    anon_parser.add_argument('--no-detect-types', action='store_false', dest='detect_types',
                           help='Disable automatic column type detection')
    anon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    anon_parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    anon_parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    
    # Deanonymize CSV command
    deanon_parser = subparsers.add_parser('deanonymize', help='Deanonymize a CSV file')
    deanon_parser.add_argument('input', nargs='?', help='Input anonymized CSV file')
    deanon_parser.add_argument('output', nargs='?', help='Output deanonymized CSV file')
    deanon_parser.add_argument('--mapping', help='Path to mapping file')
    deanon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    deanon_parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    
    # Batch anonymize command
    batch_anon_parser = subparsers.add_parser('batch-anonymize', help='Anonymize multiple CSV files')
    batch_anon_parser.add_argument('input_dir', nargs='?', help='Input directory containing CSV files')
    batch_anon_parser.add_argument('output_dir', nargs='?', help='Output directory for anonymized files')
    batch_anon_parser.add_argument('--pattern', default='*.csv', help='File pattern to match (default: *.csv)')
    batch_anon_parser.add_argument('--mapping', help='Path to save mapping file')
    batch_anon_parser.add_argument('--no-detect-types', action='store_false', dest='detect_types',
                               help='Disable automatic column type detection')
    batch_anon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    batch_anon_parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    batch_anon_parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    
    # Batch deanonymize command
    batch_deanon_parser = subparsers.add_parser('batch-deanonymize', help='Deanonymize multiple CSV files')
    batch_deanon_parser.add_argument('input_dir', nargs='?', help='Input directory containing anonymized CSV files')
    batch_deanon_parser.add_argument('output_dir', nargs='?', help='Output directory for deanonymized files')
    batch_deanon_parser.add_argument('--pattern', default='*.csv', help='File pattern to match (default: *.csv)')
    batch_deanon_parser.add_argument('--mapping', help='Path to mapping file')
    batch_deanon_parser.add_argument('--column-types', help='JSON file with column type definitions')
    batch_deanon_parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize anonymizer
    seed = args.seed if hasattr(args, 'seed') and args.seed is not None else None
    anonymizer = DataAnonymizer(seed=seed)
    
    # Check if interactive mode is enabled or if required arguments are missing
    is_interactive = False
    if hasattr(args, 'interactive') and args.interactive:
        is_interactive = True
    elif args.command == 'anonymize' and (not args.input or not args.output):
        is_interactive = True
    elif args.command == 'deanonymize' and (not args.input or not args.output or not args.mapping):
        is_interactive = True
    elif args.command == 'batch-anonymize' and (not args.input_dir or not args.output_dir):
        is_interactive = True
    elif args.command == 'batch-deanonymize' and (not args.input_dir or not args.output_dir or not args.mapping):
        is_interactive = True
    
    # Handle interactive mode
    if is_interactive:
        if args.command == 'anonymize':
            interactive_anonymize(anonymizer)
        elif args.command == 'deanonymize':
            interactive_deanonymize(anonymizer)
        elif args.command == 'batch-anonymize':
            interactive_batch_anonymize(anonymizer)
        elif args.command == 'batch-deanonymize':
            interactive_batch_deanonymize(anonymizer)
        return
    
    # Non-interactive mode - load column types if provided
    column_types = None
    if hasattr(args, 'column_types') and args.column_types:
        try:
            with open(args.column_types, 'r') as f:
                column_types = json.load(f)
        except Exception as e:
            print(f"Error loading column types file: {e}")
            return
    
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