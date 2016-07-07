# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Sensible defaults are listed here, so that RBF can function even in the case
that they aren't specified in the config file.
"""

LOG_NAME = 'root'
LOG_FMT = '%(asctime)s %(levelname)7s: %(message)s - (%(filename)s:%(lineno)d)'
MAX_LINE_LENGTH = 200
SYSCTL_PATH = '/proc/sys'
TC_END = '\033[0;m'
TC_FAIL = '\033[0;31m'
TC_PASS = '\033[0;32m'
TC_SKIP = '\033[0;33m'
TEST_DIR = 'reconbf/modules/'
