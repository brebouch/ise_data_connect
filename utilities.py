import yaml
import logging
import os


class CFG:

    @staticmethod
    def get_logger(log_name, log_path=os.getcwd(), level=logging.INFO):
        if not log_name.endswith('.log'):
            log_name = log_name + '.log'
        full_path = os.path.join(log_path, log_name.split('/')[0])
        if not os.path.exists(os.path.dirname(full_path)):
            os.makedirs(os.path.dirname(full_path))
        log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        root_logger = logging.getLogger()
        path = os.path.join(log_path, log_name)

        file_handler = logging.FileHandler("{0}".format(path))
        file_handler.setFormatter(log_formatter)
        root_logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        root_logger.addHandler(console_handler)
        root_logger.setLevel(level)
        return root_logger

    def verify_config(self, config):
        return all(self.cfg[config].values())

    def load_config(self, config="config_lab.yml"):
        with open(config, 'r') as stream:
            try:
                self.cfg = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

    def __init__(self):
        self.cfg = None
