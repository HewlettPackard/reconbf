import logging
from . import constants

# global logger
logger = logging.getLogger(constants.logger_name)
formatter = logging.Formatter(fmt=constants.logger_fmt)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
