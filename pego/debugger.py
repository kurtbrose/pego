"""
debugger facilities for parsers -- allows parser opcodes / stack
to be stepped through and inspected similar to python code

tries to be as close as possible to pdb to provide a familiar
interface for python developers
"""
import cmd
import sys

import pego


def post_mortem(t=None):
    """
    start a debugger for a pego.ParseError
    """
    if t is None:
        t = sys.exc_info()[2]
    if t is None:
        raise ValueError(
            "A valid traceback must be passed if "
            "no exception is being handled")
    if not isinstance(t, pego.ParseError):
        raise ValueError(
            "pego.post_mortem only handles instances of "
            "pego.ParseError, not {}".format(type(t)))
    dbg = Debugger(vm)


def pm():
    """
    debug the last raised pego.ParseError on the REPL
    """
    post_mortem(sys.last_traceback)


class Debugger(cmd.Cmd):
    def __init__(self, vm, completekey='tab', stdin=None, stdout=None):
        self.Cmd.__init__(self, completekey, stdin, stdout)
        self.vm = vm

    def do_where(self, arg):
        """
        w(here)
        Print the parser block-stack;
        an arrow indicates the "current block",
        which determines the context of most commands
        """
        