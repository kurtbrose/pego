import types


# MODIFIERS -- attach to another expression
# these are arbitrarily recursive
# ? + * ~ <> |
# : ->

# TERMINALS -- these can be immediately evaluated and produce error or match
# ! ''

# EQUIVALENCIES
# -> is the same as !, without the ability to capture into a local var
# (a)+ matches the same as ((a) (a)*)
# (a)? is the same as ((a) | !(None))

# COMPILED OUT -- these modify the structure of the compiled rules, but are gone by eval
# () =


# a rule is a sequence of objects for the convenience of the evaluator:
# [_MAYBE, 'a']  =>  'a'?
# [_EITHER, 'a', 'b']  =>  'a' | 'b'

# opcodes that go in rules
_BIND = object()  # : -- capture current match into name
_NOT = object()  # ~(a) -- if a fails (good case)
_MAYBE = object()  # ?
_REPEAT = object()  # +
_MAYBE_REPEAT = object()  # *
_EITHER = object()  # |
_LITERAL = object()  # <>
_EVAL = object()  # !

# marker result objects
_ERR = object()  # means an error is being thrown
_CALL = object()  # means result is TBD from next rule


_STACK_OPCODES = (
    _NOT, _MAYBE, _REPEAT, _MAYBE_REPEAT, _LITERAL, _EITHER, _BIND)


@attr.s(frozen=True)
class Grammar(object):
    '''
    A grammar, generated from an input.
    '''
    rules = attr.ib()  # labelled offsets in opcodes
    opcodes = attr.ib()  # big list of opcodes
    pyglobals = attr.ib()  # python variables to expose to eval expressions

    def from_text(cls, text):
        '''
        parse ASTs from text and construct a Grammar
        '''
        return cls(AST_GRAMMAR.parse(text))

    def parse(self, source, rule_name):
        cur_rule = self.rules[rule_name]
        src_pos = 0  # how much of source has been parsed
        # evaluate, one rule at a time
        rule_stack = [(cur_rule, 0, {})]
        traps = []  # stack of spots to trap execution e.g. try/except kind of thing
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
            cur_rule, rule_pos, binds = rule_stack.pop()
            assert rule_pos <= len(cur_rule)
            result = None
            # "call" down the stack
            while rule_pos < len(cur_rule):
                opcode = cur_rule[rule_pos]
                if type(opcode) is str:  # string literal match
                    if source[src_pos:src_pos + len(opcode)] == opcode:
                        result = cur_rule
                        src_pos += len(opcode)
                    else:
                        result = _ERR
                    break
                elif type(opcode) is types.CodeType:  # eval python expression
                    try:
                        result = eval(opcode, pyglobals, binds)
                    except Exception as e:
                        import traceback; traceback.print_exc()
                        result = _ERR
                    break
                elif type(opcode) is list:
                    rule_stack.append((opcode, 0, {}))
                    result = _CALL
                    break
                else:
                    assert opcode in _STACK_OPCODES
                    traps.append((cur_rule, rule_pos, src_pos, binds))
                rule_pos += 1
            if result is _CALL:
                continue
            # "return" up the stack
            while traps:
                cur_rule, rule_pos, last_src_pos, binds = traps.pop()
                if opcode is _BIND:
                    if result is not _ERR:
                        binds[IOU_BIND_NAME] = result
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                elif opcode is _NOT:
                    if result is _ERR:
                        result = None
                        src_pos = last_src_pos
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                        break
                    else:
                        result = _ERR
                elif opcode is _MAYBE:
                    if result is _ERR:
                        src_pos = last_src_pos
                        result = None
                    rule_stack.append((cur_rule, rule_pos + 2, binds))
                    break
                elif opcode is _MAYBE_REPEAT:
                    if result is _ERR:
                        # NOTE: rewind src_pos back to last complete match
                        src_pos = last_src_pos
                        result = IOU_INTERNAL_STATE
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                        break
                    else:
                        IOU_INTERNAL_STATE.append(result)
                        rule_stack.append((cur_rule, rule_pos + 1, binds))
                        traps.append((cur_rule, rule_pos, src_pos, binds))
                        break
                elif opcode is _REPEAT:
                    if result is _ERR:
                        if len(IOU_INTERNAL_STATE) > 0:
                            result = IOU_INTERNAL_STATE
                            src_pos = last_src_pos
                            # NOTE: rewind src_pos back to last complete match
                            rule_stack.append((cur_rule, rule_pos + 2, binds))
                            break
                    else:
                        IOU_INTERNAL_STATE.append(result)
                        rule_stack.append((cur_rule, rule_pos + 1, binds))
                        break
                elif opcode is _LITERAL:
                    if result is not _ERR:
                        result = source[last_src_pos:src_pos]
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                elif opcode is _EITHER:
                    if result is _ERR:
                        # try the other branch from the same position
                        src_pos = last_src_pos
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                        break
                else:
                    assert False, "unrecognized opcode"
        if result is _ERR:
            pass # raise a super-good exception
        return result

        # GOOD condition is rule stack empty, at last byte


AST_GRAMMAR = Grammar(
    )

# ( 'a' | 'b'*) ?  =>  [MAYBE, OR, 'a', ANY, 'b']

# MAYBE - switch result to None, stop error
# OR - if LHS hits error, stop error and go to RHS
# ANY - allocate list; keep appending match to list until error
