import sys
from io import TextIOWrapper
from pathlib import Path
from typing import Optional, TextIO, Union

from universal_data_permissions_scanner.writers.base_writers import BaseWriter, OutputFormat
from universal_data_permissions_scanner.writers.csv_writer import CSVWriter
from universal_data_permissions_scanner.writers.multi_json_exporter import MultiJsonWriter


def get_writer(filename: Optional[Union[Path, str]], output_format: OutputFormat) -> BaseWriter:
    fh = (  # pylint: disable=invalid-name
        sys.stdout if filename is None else open(filename, 'w', encoding="utf=8")  # pylint: disable=consider-using-with
    )
    writer = _get_writer(fh, output_format)
    return writer


def _get_writer(
    fh: Union[TextIO, TextIOWrapper], output_format: OutputFormat  # pylint: disable=(invalid-name)
) -> BaseWriter:
    if output_format is OutputFormat.MULTI_JSON:
        return MultiJsonWriter(fh)
    if output_format is OutputFormat.CSV:
        return CSVWriter(fh)
    raise WriterNotFoundException("Output format not support")


class WriterNotFoundException(BaseException):
    """The writer isn't defined."""
