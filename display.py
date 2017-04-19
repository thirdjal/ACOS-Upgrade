#
# Copyright 2017, John Lawrence <jlawrence AT a10networks DOT com>
#
import sys


def debug(msg, head="DEBUG"):
    head = Color.bold + Color.FG.lightgrey + " " + str(head) + ": " + Color.reset
    msg = Color.FG.lightgrey + str(msg) + Color.reset
    _message(head, msg)
    return msg


def error(msg, head="ERROR"):
    head = Color.bold + Color.FG.red + " " + str(head) + ": " + Color.reset
    msg = Color.FG.red + str(msg) + Color.reset
    _message(head, msg)
    return msg


def fatal(msg, head="FATAL"):
    head = Color.bold + Color.BG.red + Color.FG.white + " " + str(head) + ": " + Color.reset
    msg = Color.BG.red + Color.FG.white + str(msg) + " " + Color.reset
    _message(head, msg)
    return msg


def info(msg, head="INFO"):
    head = Color.bold + Color.FG.lightblue + " " + str(head) + ": " + Color.reset
    _message(head, msg)
    return msg


def warn(msg, head="WARNING"):
    head = Color.bold + Color.FG.orange + " " + str(head) + ": " + Color.reset
    msg = Color.FG.orange + str(msg) + Color.reset
    _message(head, msg)
    return msg


def _message(head, msg):
    print("{}{}".format(head, msg))
    return msg


def write(msg):
    print(msg)


def prompt(msg):
    # For Python 3.x use 'input' instead of 'raw_input'
    if sys.version_info.major >= 3:
        response = input(str(msg))
    else:
        response = raw_input(str(msg))
    return response


def header(line, version=None, author=None):
    print(Color.FG.lightblue)
    print("{:-^80}".format("-"))
    print("{: ^80}".format(" "))
    if version:
        print("{: ^80}".format(" "))
    if author:
        print("{: ^80}".format(" "))
    print(Color.FG.orange + "{: ^80}".format(str(line)) + Color.FG.lightblue)
    print("{: ^80}".format(" "))
    if version:
        v = "v: " + str(version)
        print(Color.FG.lightgrey + "{:>79}".format(v) + Color.FG.lightblue)
    if author:
        a = str(author)
        print(Color.FG.lightgrey + "{:>79}".format(a) + Color.FG.lightblue)
    print("{:-^80}".format("-"))
    print(Color.reset)


class Color:
    reset = '\033[0m'
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strikethrough = '\033[09m'
    invisible = '\033[08m'

    class BG:
        """
        A list of ANSI escaped sequences for setting the background color
        """
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'
        orange = '\033[43m'
        blue = '\033[44m'
        purple = '\033[45m'
        cyan = '\033[46m'
        lightgrey = '\033[47m'

    class FG:
        """
        A list of ANSI escaped sequences for setting the foreground color
        """
        black = '\033[30m'
        red = '\033[31m'
        green = '\033[32m'
        orange = '\033[33m'
        blue = '\033[34m'
        purple = '\033[35m'
        cyan = '\033[36m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'
        lightred = '\033[91m'
        lightgreen = '\033[92m'
        yellow = '\033[93m'
        lightblue = '\033[94m'
        pink = '\033[95m'
        lightcyan = '\033[96m'
        white = '\033[97m'


if __name__ == '__main__':
    info("I'm calling out that this one is 'INFO'.")
    debug("...and this is a debug message.")
    error("This time you are seeing an error.")
    warn("I'm giving you just one warning.")
    fatal("The sky is falling!!!")
