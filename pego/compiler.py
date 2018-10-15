'''
compiler provides mechanisms to translate rules into a form
that is executable by the VM
'''
import copy

from .vm import IF, NOT, ANYTHING, SRC_POP, ERR, CALL


class Ref(object):
    def __init__(self, rulename):
        self.rulename = rulename

    def __repr__(self):
        return "<Ref-{}>".format(self.rulename)


_py = lambda code: compile(code, '<string>', 'eval')


class _SymbolTable(object):
    '''
    keeps track of reverse lookups for callable rules so that stack traces
    can be nicely labelled
    '''
    def __init__(self, callable_rules):
        self._id_name_map = {id(val): key for key, val in callable_rules.items()}

    def block_name(self, block):
        return self._id_name_map.get(id(block))


def compile_rules(rule_dict):
    # TODO: support rules with args
    # recursive copy of rule opcodes, since we are going to mutate in place
    compiled_rules = copy.deepcopy(rule_dict)  # TODO: deepcopy might break user objects, use a lighter touch
    callable_rules = {
        name: [  # TODO: chaining multiple definitions
            IF,  # if args-match, then body, else error
            [NOT, ANYTHING, SRC_POP],  # args  -- TODO: non-empty arg expression handling
            rule,  # body -- mutate-in-place below will fix it up
            [SRC_POP, ERR]]
        for name, rule in compiled_rules.items()}
    stack = compiled_rules.values()
    seen = set()
    while stack:
        cur = stack.pop()
        assert type(cur) is list
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        # recurse to get all stacks
        stack.extend([code for code in cur if type(code) is list])
        for pos, opcode in enumerate(cur):
            if isinstance(opcode, Ref):  # replace refs with calls
                if opcode.rulename not in rule_dict:
                    raise ValueError('reference to rule {} not in grammar'.format(opcode.rulename))
                # TODO: non-empty calling arg sequence
                cur[pos:pos + 1] = [CALL, [], callable_rules[opcode.rulename]]
    return compiled_rules, _SymbolTable(callable_rules)
