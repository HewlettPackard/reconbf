"""
Sensible defaults are listed here, so that RBF can function even in the case
that they aren't specified in the config file.
"""

CSV_SEPARATOR = '|'
LOG_NAME = 'root'
LOG_FMT = '%(asctime)s %(levelname)7s: %(message)s - (%(filename)s:%(lineno)d)'
MAX_LINE_LENGTH = 200
SYSCTL_PATH = '/proc/sys'
TC_END = '\033[0;m'
TC_FAIL = '\033[0;31m'
TC_PASS = '\033[0;32m'
TC_SKIP = '\033[0;33m'
TEST_DIR = 'reconbf/modules/'
