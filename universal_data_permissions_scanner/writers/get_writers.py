import sys
from io import TextIOWrapper
from pathlib import Path
from contextlib import contextmanager
from typing import Optional, TextIO, Union, Generator, Any

from universal_data_permissions_scanner.writers.base_writers import BaseWriter, OutputFormat
from universal_data_permissions_scanner.writers.csv_writer import CSVWriter
from universal_data_permissions_scanner.writers.multi_json_exporter import MultiJsonWriter


@contextmanager
def open_writer(filename: Optional[Union[Path, str]], output_format: OutputFormat) -> Generator[BaseWriter, Any, None]:
    fh = (  # pylint: disable=invalid-name
        sys.stdout if filename is None else open(filename, 'w', encoding="utf=8")  # pylint: disable=consider-using-with
    )
    with _open_writer(fh, output_format) as writer:
        yield writer


@contextmanager
def _open_writer(
    fh: Union[TextIO, TextIOWrapper], output_format: OutputFormat  # pylint: disable=(invalid-name)
) -> Generator[BaseWriter, Any, None]:
    if output_format is OutputFormat.MULTI_JSON:
        with MultiJsonWriter.open(fh) as writer:
            yield writer
    elif output_format is OutputFormat.CSV:
        with CSVWriter.open(fh) as writer:
            yield writer
    else:
        raise WriterNotFoundException("Output format not support")


class WriterNotFoundException(BaseException):
    """The writer isn't defined."""
