"""Module for writers."""
from universal_data_permissions_scanner.writers.base_writers import BaseWriter, OutputFormat
from universal_data_permissions_scanner.writers.csv_writer import CSVWriter
from universal_data_permissions_scanner.writers.get_writers import get_writer
from universal_data_permissions_scanner.writers.multi_json_exporter import MultiJsonWriter

__all__ = ["OutputFormat", "BaseWriter", "CSVWriter", "MultiJsonWriter", "get_writer"]
