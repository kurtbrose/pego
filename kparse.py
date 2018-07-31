
# MODIFIERS -- attach to another expression
# these are arbitrarily recursive
# ? + * ~ <> |

# TERMINALS -- these can be immediately evaluated and produce error or match
# ! '' : ->

# EQUIVALENCIES
# -> is the same as !, without the ability to capture into a local var
# (a)+ matches the same as ((a) (a)*)
# (a)? is the same as ((a) | !(None))

# COMPILED OUT -- these modify the structure of the compiled rules, but are gone by eval
# () =


# a rule is a sequence of objects for the convenience of the evaluator:
# [_MAYBE, 'a']  =>  'a'?
# [_EITHER, 'a', 'b']  =>  'a' | 'b'

_Match = attr.make_class('_Match', ['rule', 'start', 'end'], frozen=True)
_BIND = object()  # : -- capture current match into name
_NOT = object()  # ~(a) -- if a fails (good case)
_HALT = object()  # ~(a) -- if a succeeds (bad case)
_MAYBE = object()  # ?
_REPEAT = object()  # +
_MAYBE_REPEAT = object()  # *
_EITHER = object()  # |
_LITERAL = object()  # <>
_ERR = object()  # means an error is being thrown


_STACK_OPCODES = (
    _NOT, _MAYBE, _REPEAT, _MAYBE_REPEAT, _LITERAL, _EITHER)


@attr.s(frozen=True)
class Grammar(object):
    '''
    A grammar, generated from an input.
    '''
    rules = attr.ib()  # labelled offsets in opcodes
    opcodes = attr.ib()  # big list of opcodes

    def from_text(cls, text):
        '''
        parse ASTs from text and construct a Grammar
        '''
        return cls(AST_GRAMMAR.parse(text))

    def parse(self, source, rule_name):
        cur_rule = self.rules[rule_name]
        src_pos = 0  # how much of source has been parsed
        # evaluate, one rule at a time
        rule_stack = [(cur_rule, 0, [])]
        match_stack = []
        # stack keeps track of matched rules, matched opcodes w/in rule
        # algorithm proceeds as follows:
        # 1- try to match current rule
        # 2- if failed, back up and find a peer rule
        #    2A - if this stack unwind gets to the root, raise a good exception
        # 3-
        while src_pos != len(source):  # keep going until source parsed (or error)
            if not rule_stack:
                # TODO: cleaner error message
                raise ValueError('extra input')
            cur_rule, rule_pos, opcode_matches = rule_stack.pop()
            assert rule_pos <= len(cur_rule)
            result = None
            while rule_pos != len(cur_rule):
                opcode = cur_rule[rule_pos]
                if result is _ERR:
                    # child call crashed
                    if opcode is _NOT:
                        pass
                if type(opcode) is str:
                    if source[src_pos:src_pos + len(opcode)] == opcode:
                        result = cur_rule
                        opcode_matches.append((rule_pos, src_pos))
                        src_pos += len(opcode)
                    else:
                        result = _ERR
                elif opcode in _STACK_OPCODES:
                    match_stack.append((rule_pos, src_pos))  
                    # check match_stack / rule_stack
                    continue

                if result is _ERR:
                    # halt execution, start unwinding
                    while opcode_matches:
                        rule_pos, src_pos = match_stack.pop()
                        opcode = cur_rule[rule_pos]
                        if opcode is _NOT:
                            pass
                    break
                else:
                    rule_pos += 1


            if err:
                while 1:
                    cur_rule = rule_stack.pop()
                    if cur_rule is _MAYBE:

                pass  # try to roll back out to an alternate rule via | or ?
        if err:
            pass # raise a super-good exception
        return match_stack[-1]


AST_GRAMMAR = Grammar(
    )

# ( 'a' | 'b'*) ?  =>  [MAYBE, [OR, ['a'], [ANY, ['b']]]]

# MAYBE - switch result to None, stop error
# OR - if LHS hits error, stop error and go to RHS
# ANY - allocate list; keep appending match to list until error
