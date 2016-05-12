import logging
from . import constants

# global logger
logger = logging.getLogger(constants.LOG_NAME)
formatter = logging.Formatter(fmt=constants.LOG_FMT)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
