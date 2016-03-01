from .logger import logger
import os


class TestProfile:
    def __init__(self, profile_loc):
        self.profile_loc = os.path.abspath(profile_loc)
        self.config_dir = os.path.abspath(profile_loc + '/config')
        self.scripts_dir = os.path.abspath(profile_loc + '/scripts')
        self.modules_dir = os.path.abspath(profile_loc + '/modules')
        self.templates_dir = os.path.abspath(profile_loc + '/templates')
        self.rbf_cfg = os.path.abspath(self.config_dir + '/rbf.cfg')

    def is_valid(self):
        # valid profile directories will have:
        #  /config, /scripts, /modules/, /templates, /config/rbf.cfg
        # if any of these don't exist, log errors and return False

        reasons = []

        if not os.path.isdir(self.profile_loc):
            reasons.append("Specified profile location doesn't exist")
        else:
            logger.debug("[*] Using profile: {}".format(self.profile_loc))

        if not os.path.isdir(self.config_dir):
            reasons.append("Specified profile doesn't contain config dir")

        if not os.path.isdir(self.scripts_dir):
            reasons.append("Specified profile doesn't contain scripts dir")

        if not os.path.isdir(self.modules_dir):
            reasons.append("Specified profile doesn't contain modules dir")

        if not os.path.isdir(self.templates_dir):
            reasons.append("Specified profile doesn't contain templates dir")

        if not os.path.exists(self.rbf_cfg):
            reasons.append("Specified profile doesn't contain rbf.cfg")

        if len(reasons) == 0:
            return True
        else:
            for reason in reasons:
                logger.error('[-] {}'.format(reason))
            return False

    @property
    def profile_loc(self):
        return self.profile_loc

    @property
    def config_dir(self):
        return self.config_dir

    @property
    def scripts_dir(self):
        return self.scripts_dir

    @property
    def modules_dir(self):
        return self.modules_dir

    @property
    def templates_dir(self):
        return self.templates_dir

    @property
    def rbf_cfg(self):
        return self.rbf_cfg
