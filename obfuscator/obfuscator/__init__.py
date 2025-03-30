"""
Core functionality of the Obfuscator data anonymization library.
"""

from .anonymizer import DataAnonymizer
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
    anonymize_numeric,
    anonymize_string,
    anonymize_json,
    anonymize_binary,
    anonymize_geography
)

__all__ = [
    'DataAnonymizer',
    'DataTypeDetector',
    'anonymize_uuid',
    'anonymize_email',
    'anonymize_phone',
    'anonymize_name',
    'anonymize_address',
    'anonymize_ip',
    'anonymize_datetime',
    'anonymize_boolean', 
    'anonymize_numeric',
    'anonymize_string',
    'anonymize_json',
    'anonymize_binary',
    'anonymize_geography'
]