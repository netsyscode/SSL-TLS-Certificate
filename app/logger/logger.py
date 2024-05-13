
'''
    2023/09/21
    Created Ver. 1.0
    
    01/24/24
    Remove representative logger API
'''

from datetime import datetime, timezone
import os
import colorama
from colorama import Fore, Style
import logging

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

class Logger:
    
    # To have color printed console message,
    # we need to build a costomized console handler
    class ColoredConsoleHandler(logging.StreamHandler):
    
        # emit will be called automatically once we envoke
        # logging.debug or etc.
        def emit(self, record:logging.LogRecord):
        
            # set color based on the logging level
            '''
            match record.levelno:
                case logging.DEBUG:
                    text_color = Fore.GREEN
                case logging.INFO:
                    text_color = Fore.BLUE
                case logging.WARNING:
                    text_color = Fore.YELLOW
                case logging.ERROR:
                    text_color = Fore.RED
                case logging.CRITICAL:
                    text_color = Fore.RED
                case _:
                    text_color = Fore.WHITE
            '''

            if record.levelno == logging.DEBUG:
                text_color = Fore.GREEN
            elif record.levelno== logging.INFO:
                text_color = Fore.BLUE
            elif record.levelno == logging.WARNING:
                text_color = Fore.YELLOW
            elif record.levelno == logging.ERROR:
                text_color = Fore.RED
            elif record.levelno == logging.CRITICAL:
                text_color = Fore.RED
            else:
                text_color = Fore.WHITE

            output_msg = self.format(record)
            output_msg = f"{text_color}{output_msg}{Style.RESET_ALL}"
            print(output_msg)

    # __new__ should be responsible for instance creation
    # so the return value must be an instance of the class
    def  __new__(self,
                  log_file_extension_name:str = ".log",
                  log_file_dir_path:str = os.path.join(os.path.dirname(__file__), r"../data/log"),
                  log_file_level_no:int = logging.INFO,
                  log_console_level_no:int = logging.DEBUG):
        
        instance = super().__new__(self)
        
        colorama.init(autoreset=True)
        current_datetime = datetime.now(timezone.utc)

        log_file_name = str(current_datetime.date()) + "_" + str(current_datetime.time())
        log_file_name = log_file_name.replace(":", "_").replace(".", "_") + log_file_extension_name
        self.log_file_path = os.path.abspath(os.path.join(log_file_dir_path, log_file_name))

        # create the logger
        self.logger = logging.getLogger("projectLogger")
        self.logger.setLevel(logging.DEBUG)

        # create two log handler, one for file, one for console
        file_handler = logging.FileHandler(self.log_file_path)
        file_handler.setLevel(log_file_level_no)
        console_handler = Logger.ColoredConsoleHandler()    # NOTE: self-defined handler
        console_handler.setLevel(log_console_level_no)

        # define log message format
        formatter = logging.Formatter("%(asctime)s - %(name)s:%(lineno)d - %(levelname)s\n%(message)s")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        return instance

    # @deprecated
    # use logging.debug(msg) directly
    '''
    def dumpLog(self, level:int, msg:str):
        
        match level:
            case logging.DEBUG:
                self.logger.debug(msg)
            case logging.INFO:
                self.logger.info(msg)
            case logging.WARNING:
                self.logger.warning(msg)
            case logging.ERROR:
                self.logger.error(msg)
            case logging.CRITICAL:
                self.logger.critical(msg)
            case _:
                # We can just put 0 into level field
                print(msg)
    '''

# The project has only one logger
# If you want to change its field, do it here
my_logger = Logger(log_file_level_no=INFO, log_console_level_no=INFO).logger


