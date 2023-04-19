import logging
from typing import Optional

LOGGER: Optional[logging.Logger] = None


def _create_logger(debug: bool) -> logging.Logger:
    """Provides a logger in case one is not provided.

    Args:
        debug (bool): Should logs be in debug

    Returns:
        Logger: Python logger
    """
    logger = logging.getLogger('aws_ptrp')
    level = logging.INFO if not debug else logging.DEBUG
    logger.setLevel(level)

    if logger.handlers:
        return logger

    ch = logging.StreamHandler()  # pylint: disable=C0103
    ch.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


def get_ptrp_logger() -> logging.Logger:
    global LOGGER  # pylint: disable=W0603
    if LOGGER:
        return LOGGER
    else:
        LOGGER = _create_logger(debug=False)
        return LOGGER


def set_ptrp_logger(logger: logging.Logger):
    global LOGGER  # pylint: disable=W0603
    LOGGER = logger
