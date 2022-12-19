import sys
from io import TextIOWrapper
from pathlib import Path
from typing import TextIO, Union

from authz_analyzer.writers.base_writers import OutputFormat
from authz_analyzer.writers.csv_writer import CSVWriter
from authz_analyzer.writers.multi_json_exporter import MultiJsonWriter


def get_writer(filename: Union[Path, str], output_format: OutputFormat):
    fh = sys.stdout if filename is None else open(filename, 'w', encoding="utf=8")
    writer = _get_writer(fh, output_format)
    return writer


def _get_writer(fh: Union[TextIO, TextIOWrapper], output_format: OutputFormat):
    if output_format is OutputFormat.MULTI_JSON:
        return MultiJsonWriter(fh)
    if output_format is OutputFormat.CSV:
        return CSVWriter(fh)
    raise WriterNotFoundException("Output format not support")


class WriterNotFoundException(BaseException):
    """The writer isn't defined."""
