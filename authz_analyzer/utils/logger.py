import logging


def get_logger(debug: bool):
    """Provides a logger in case one is not provided.

    Args:
        debug (bool): Should logs be in debug

    Returns:
        Logger: Python logger
    """
    logger = logging.getLogger('authz-analyzer')
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
