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
_ANYTHING = object()  # match a single char of anything, like . in regex

# marker result objects
_ERR = object()  # means an error is being thrown
_CALL = object()  # means result is TBD from next rule


_STACK_OPCODES = (
    _NOT, _MAYBE, _REPEAT, _MAYBE_REPEAT, _LITERAL, _EITHER, _BIND)


class Grammar(object):
    '''
    A grammar, generated from an input.
    '''
    # rules = attr.ib()
    #TODO: switch rules to labelled offsets in opcodes
    # opcodes = attr.ib()  # big list of opcodes
    # pyglobals = attr.ib()  # python variables to expose to eval expressions
    def __init__(self, rules, pyglobals):
        self.rules, self.pyglobals = rules, pyglobals

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
        # stack keeps track of matched rules, matched opcodes w/in rule
        is_stopping = False
        while not is_stopping:  # keep going until source parsed (or error)
            if not rule_stack:
                # TODO: cleaner error message
                raise ValueError('extra input: {}'.format(repr(source[src_pos:])))
            cur_rule, rule_pos, binds = rule_stack.pop()
            assert rule_pos <= len(cur_rule)
            result = None
            # "call" down the stack
            while rule_pos < len(cur_rule):
                opcode = cur_rule[rule_pos]
                if type(opcode) is str:  # string literal match
                    if source[src_pos:src_pos + len(opcode)] == opcode:
                        result = opcode
                        src_pos += len(opcode)
                    else:
                        result = _ERR
                    break
                elif type(opcode) is types.CodeType:  # eval python expression
                    try:
                        result = eval(opcode, self.pyglobals, binds)
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
                    if opcode in (_REPEAT, _MAYBE_REPEAT):
                        state = []
                    elif opcode is _BIND:
                        state = cur_rule[rule_pos + 1]
                    else:
                        state = None
                    traps.append((cur_rule, rule_pos, src_pos, binds, state))
                    if opcode is _BIND:
                        rule_pos += 1  # advance 1 more since pos + 1 is bind name
                rule_pos += 1
            if result is _CALL:
                continue
            is_stopping = (src_pos == len(source))
            # "return" up the stack
            while traps:
                cur_rule, rule_pos, last_src_pos, binds, state = traps.pop()
                opcode = cur_rule[rule_pos]
                if opcode is _BIND:
                    # [ ..., _BIND, name, expression, ... ]
                    if result is not _ERR:
                        binds[state] = result
                        rule_stack.append((cur_rule, rule_pos + 3, binds))
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
                        result = state
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                        break
                    elif is_stopping:
                        state.append(result)
                        result = state
                    else:
                        state.append(result)
                        rule_stack.append((cur_rule, rule_pos + 1, binds))
                        traps.append((cur_rule, rule_pos, src_pos, binds, state))
                        break
                elif opcode is _REPEAT:
                    if result is _ERR:
                        if len(state) > 0:
                            result = state
                            src_pos = last_src_pos
                            # NOTE: rewind src_pos back to last complete match
                            rule_stack.append((cur_rule, rule_pos + 2, binds))
                            break
                    elif is_stopping:
                        state.append(result)
                        result = state
                    else:
                        state.append(result)
                        rule_stack.append((cur_rule, rule_pos + 1, binds))
                        traps.append((cur_rule, rule_pos, src_pos, binds, state))
                        break
                elif opcode is _LITERAL:
                    if result is not _ERR:
                        result = source[last_src_pos:src_pos]
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                elif opcode is _EITHER:
                    # [ ..., _EITHER, branch1, branch2, ... ]
                    if result is _ERR:
                        # try the other branch from the same position
                        src_pos = last_src_pos
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                        break
                    else:
                        rule_stack.append((cur_rule, rule_pos + 3, binds))
                else:
                    assert False, "unrecognized opcode"
        if result is _ERR:
            raise Exception('oh no!')  # raise a super-good exception
        return result

        # GOOD condition is rule stack empty, at last byte


class _Ref(object):
    def __init__(self, rulename):
        self.rulename = rulename


_py = lambda code: compile(code, '<string>', 'eval')


_BOOTSTRAP1_GRAMMAR = Grammar(
    {
        'ws': [_REPEAT, [_EITHER, ' ',  '\n']],
        'brk': [_Ref('ws'), _MAYBE, ['#', _MAYBE_REPEAT, [_NOT, '\n',], '\n']],
        'grammar': [_BIND, 'rules', [_REPEAT, _Ref('rule')], _py('dict(rules)')],
        'rule': [_BIND, 'name', _Ref('name'), '= ', _BIND, 'expr', _Ref('expr'), _py('(name, expr)')],
        'name': [_LITERAL, [_REPEAT, [_NOT, _Ref('ws'), _ANYTHING]]],
        'expr': [],
    },
    {
        'Grammar': Grammar
    }
)


# the complete grammar, expressed using as few symbols as possible
# in order to make the first bootstrap grammar which must be hand
# coded as simple as possible
_BOOTSTRAP2_GRAMMAR = '''
'''


# grammar that describes the grammar, described in a fully
# semantic fashion
_GRAMMAR_GRAMMAR = r'''
ws = (' ' | '\t' | '\n')+
brk = ws ('#' (~'#')* '\n')?
grammar = (brk? rule)*:rules -> dict(rules)
rule = name brk '=' brk expr -> (name, expr)
expr = leaf_expr | either | bind | maybe_repeat | repeat
# these are unambiguous because they have a leading char
parens = '(' expr:inner ')' -> [inner]
not = '~' expr:inner -> [_NOT, inner]
literal = '<' expr:inner '>' -> [_LITERAL, inner]
str = '\'' <('\\\'' | (~'\'' .))*>:val '\'' -> val
py = '!(' <.*>:code ')' -> _py(code)
leaf_expr = parens | not | literal | str | py
# these need to have a strict order since they do not have a leading char
either = either1:first brk '|' brk either1:second -> [_EITHER, first] + second
either1 = leaf_expr | maybe_repeat | repeat | bind
bind = (leaf_expr | maybe_repeat | repeat):inner ':' name:name -> [_BIND, name, inner]
maybe_repeat = leaf_expr:inner '+' -> [_MAYBE_REPEAT, inner]
repeat = leaf_expr:inner '*' -> [_REPEAT, inner]
'''


# ( 'a' | 'b'*) ?  =>  [MAYBE, OR, 'a', ANY, 'b']

# MAYBE - switch result to None, stop error
# OR - if LHS hits error, stop error and go to RHS
# ANY - allocate list; keep appending match to list until error


if __name__ == "__main__":
    def chk(rule, src, result):
        assert Grammar({'test': rule}, {}).parse(src, 'test') == result
    chk(['aaa'], 'aaa', 'aaa')
    chk([_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([_MAYBE_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([_MAYBE_REPEAT, 'a'], '', [])
    chk([_EITHER, 'a', 'b'], 'a', 'a')
    chk([_EITHER, 'a', 'b'], 'b', 'b')
    chk([_LITERAL, _REPEAT, 'a'], 'a' * 8, 'a' * 8)
    chk([_NOT, 'a', 'b'], 'b', 'b')
    chk([_py('1')], '', 1)
    chk([_BIND, 'foo', _py('1'), _py('foo')], '', 1)
