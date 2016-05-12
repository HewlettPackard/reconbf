"""
Sensible defaults are listed here, so that RBF can function even in the case
that they aren't specified in the config file.
"""

csv_separator = '|'
config_dir = 'config'
file_perms_file = 'config/file_controls.cfg'
logger_name = 'root'
logger_fmt = ('%(asctime)s %(levelname)7s: %(message)s ' +
              '- (%(filename)s:%(lineno)d)')
max_line_length = 200
sysctl_path = '/proc/sys'
term_color_end = '\033[0;m'
term_color_fail = '\033[0;31m'
term_color_pass = '\033[0;32m'
term_color_skip = '\033[0;33m'
test_dir = 'reconbf/modules/'
trace_line_seq = "     "
