import sys
import logging

this = sys.modules[__name__]
this.logger = None
this.info = None
this.msg = None
this.warn = None
this.error = None
this.err = None
this.fatal = None
this.debug = None

this.DEBUG = logging.DEBUG
this.DBG = logging.DEBUG
this.INFO = logging.INFO
this.MSG = logging.INFO + int((logging.WARN-logging.INFO)/2)
this.MESSAGE = this.MSG
this.WARN = logging.WARN
this.ERROR = logging.ERROR
this.ERR = logging.ERROR
this.FATAL = logging.FATAL


class logger_wrapper:
    def __init__(self, name="lsgtools"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(this.MESSAGE)

    def info(self, *args):
        self.logger.info("".join(args))

    def msg(self, *args):
        self.logger.log(this.MSG, "".join(args))

    def warn(self, *args):
        self.logger.warning("".join(args))

    def error(self, *args):
        self.logger.error("".join(args))

    def fatal(self, *args):
        self.logger.critical("".join(args))

    def debug(self, *args):
        import inspect
        frameinfo = inspect.getouterframes(inspect.currentframe())
        (frame, source, lineno, func, lines, index) = frameinfo[1]
        caller_log = "%s:%s::" % (func, lineno)
        self.logger.debug(caller_log + "".join(args))

    def setLevel(self, level):
        self.logger.setLevel(level)

    def setName(self, name):
        self.logger.name = name


def _debug(*args):
    this.logger.debug("".join(args))


def _info(*args):
    this.logger.info("".join(args))


def _msg(*args):
    this.logger.msg("".join(args))


def _warn(*args):
    this.logger.warn("".join(args))


def _error(*args):
    this.logger.error("".join(args))


def _fatal(*args):
    this.logger.fatal("".join(args))


def create_logger(name="lsgtools"):
    logger = logger_wrapper(name)
    return logger


def setup(name="lsgtools"):
    if None is this.logger:
        logging.basicConfig()
        logging.addLevelName(this.MSG, "MESSAGE")
        this.logger = create_logger(name)
        this.debug = _debug
        this.info = _info
        this.msg = _msg
        this.warn = _warn
        this.error = _error
        this.err = _error
        this.fatal = _fatal


def set_verbosity(v):
    if 0 == v:
        # Default if no -v has been passed, so just ignore
        return
    levels = [this.DBG, this.INFO, this.MSG, this.WARN, this.ERR, this.FATAL]
    if v in levels:
        level = v
    else:
        # This serves receiving -v set from a consuming script. As the default level is MESSAGE,
        # this can go yet INFO or DEBUG, so max -vv.
        if 1 == v:
            level = this.INFO
        else:
            level = this.DEBUG
    this.logger.setLevel(level)
    # Set same level on the root logger, if unconfigured
    if 0 == logging.getLogger().getEffectiveLevel():
        logging.getLogger().setLevel(level)


def set_name(name):
    this.logger.setName(name)
