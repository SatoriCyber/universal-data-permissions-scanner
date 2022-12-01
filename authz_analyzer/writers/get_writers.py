import sys
from io import TextIOWrapper
from pathlib import Path
from typing import TextIO, Union

from authz_analyzer.writers.base_writers import OutputFormat
from authz_analyzer.writers.csv_writer import CSVWriter
from authz_analyzer.writers.multi_json_exporter import MultiJsonWriter


def get_writer(filename: Union[Path, str], format: OutputFormat):
    fh = sys.stdout if filename is None else open(filename, 'w', encoding="utf=8")
    writer = _get_writer(fh, format)
    writer.write_header()
    return writer


def _get_writer(fh: Union[TextIO, TextIOWrapper], format: OutputFormat):
    if format is OutputFormat.MultiJson:
        return MultiJsonWriter(fh)
    elif format is OutputFormat.Csv:
        return CSVWriter(fh)
    else:
        raise BaseException("Output format not support")  # TODO: Better handle
