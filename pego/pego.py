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
# [_OR, 'a', 'b']  =>  'a' | 'b'


class Opcode(object):
    '''Parsing VM Opcodes'''
    def __init__(self, name, description):
        self.name, self.description = name, description

    def __repr__(self):
        return '<[' + self.name + ']>'


def _opc(name, description):
    globals()['_' + name] = Opcode(name, description)


_opc("BIND", "a:name -- capture current match into name")
_opc("NOT", "~(a) -- if a fails (good case)")
_opc("MAYBE", "a? -- optional")
_opc("REPEAT", "a+ -- repeat, at least one")
_opc("MAYBE_REPEAT", "a* -- optional repeating")
_opc("OR", "a | b -- either match a or b")
_opc("LITERAL", "<a> -- throw away result and return accepted input")
_opc("ANYTHING", ". -- match a single instance of anything")
_opc("CHECK", "?(py) check that the current result is truthy")
_opc("IF", "a + b | c + d -- like OR but once a or c matches, b or d are no longer optional")

# marker result objects
_ERR = object()  # means an error is being thrown
_CALL = object()  # means result is TBD from next rule


_STACK_OPCODES = (
    _NOT, _MAYBE, _REPEAT, _MAYBE_REPEAT, _LITERAL, _OR, _BIND)


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

    def from_text(cls, text, pyglobals=None):
        '''
        parse ASTs from text and construct a Grammar
        '''
        return cls(AST_GRAMMAR.parse(text), pyglobals=pyglobals or {})


class Parser(object):
    '''Python Parser -- compile one of these to build a parser'''
    def __init__(self, grammar, rule_name):
        self.grammar, self.rule_name = grammar, rule_name

    @classmethod
    def compile(cls, grammar, rule_name):
        '''compile a given grammar + rule_name and get back a parser'''
        # TODO: accept a Rule class which knows its source Grammar?
        return PyParser(grammar, rule_name)

    def parse(self, source):
        # TODO: deterministic UTF-8 encoding of source and rules strings?
        str_source = isinstance(source, basestring)
        cur_rule = self.grammar.rules[self.rule_name]
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
                if opcode is _ANYTHING:
                    if src_pos < len(source):
                        result = source[src_pos]
                        src_pos += 1
                        rule_pos += 1
                    else:
                        result = _ERR
                    break
                elif type(opcode) is str:  # string literal match
                    if str_source and source[src_pos:src_pos + len(opcode)] == opcode:
                        result = opcode
                        src_pos += len(opcode)
                    elif not str_source and source[src_pos] == opcode:
                        # sequence matching
                        result = opcode
                        src_pos += 1
                    else:
                        result = _ERR
                    break
                elif type(opcode) is types.CodeType:  # eval python expression
                    try:
                        result = eval(opcode, self.grammar.pyglobals, binds)
                    except Exception as e:
                        import traceback; traceback.print_exc()
                        result = _ERR
                    break
                elif type(opcode) is list:
                    # internal flow control w/in a rule; same scope
                    rule_stack.append((cur_rule, rule_pos, binds))
                    rule_stack.append((opcode, 0, binds))
                elif opcode is _CALL:
                    # TODO: working towards getting this going
                    # with the proper ometa semantics
                    rule_pos += 1
                    argmap = cur_rule[rule_pos]
                    assert type(argmap) is dict
                    args = {}
                    for argname, argref in argmap.items():
                        args[argname] = binds[argref]
                    rule_stack.append((cur_rule, rule_pos, binds))
                    rule_stack.append((opcode, 0, args))
                    result = _CALL
                    break
                else:
                    assert opcode in _STACK_OPCODES, opcode
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
                elif opcode is _OR:
                    # [ ..., _OR, branch1, branch2, ... ]
                    if result is _ERR:
                        # try the other branch from the same position
                        src_pos = last_src_pos
                        rule_stack.append((cur_rule, rule_pos + 3, binds))
                        break
                    else:
                        rule_stack.append((cur_rule, rule_pos + 2, binds))
                elif opcode is _IF:
                    # [ ..., _IF, cond1, exec1, cond2, exec2, ...]
                    if result is _ERR:
                        # try the other branch from the same position
                        src_pos = last_src_pos
                        rule_stack.append((cur_rule, rule_pos))
                else:
                    assert False, "unrecognized opcode"
        if result is _ERR:
            raise Exception('oh no!')  # raise a super-good exception
        return result

        # GOOD condition is rule stack empty, at last byte


class _Ref(object):
    def __init__(self, rulename):
        self.rulename = rulename


class _Call(object):
    def __init__(self, rulename, arglist):
        self.rulename, self.arglist = rulename, arglist


_py = lambda code: compile(code, '<string>', 'eval')


_BOOTSTRAP1_GRAMMAR = Grammar(
    {
        'ws': [_REPEAT, [_OR, ' ',  '\n']],
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

# builtins
#    token, anything (.), end (matches end of input)
# grammar reference
#    a grammar may refer to rules from another grammar via
#    dotted notation; e.g. to reference the select rule from
#    a sql grammar: sql.select
#    these grammar references are passed in
# stdlib
#    c_comment, cpp_comment, py_comment

# grammar that describes the grammar, described in a fully
# semantic fashion
_GRAMMAR_GRAMMAR = r'''
ws = (' ' | '\t' | '\n')+
brk = ws ('#' (~'#')* '\n')?
# TODO: better way to express this natively -- maybe support regex syntax
letter = .:c ?(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
digit = .:c ?(c in '1234567890')
name = <letter | '_' (letter | digit | '_')*>
grammar = (brk? rule)*:rules -> dict(rules)
rule = name args "=" brk expr -> (name, args, expr)
args = arg*
arg = (name?:match ':' name:bindname) -> (match, bindname)
expr = (leaf_expr | either | bind | maybe_repeat | repeat):body ("->" pyc:action -> body + [action])
# these are unambiguous because they have a leading char
parens = '(' expr:inner ')' -> [inner]
not = '~' expr:inner -> [_NOT, inner]
literal = '<' expr:inner '>' -> [_LITERAL, inner]
str = '\'' <('\\\'' | (~'\'' .))*>:val '\'' -> val
tok = '\"' <('\\\"' | (~'\"' .))*>:val '\"' `token(val)`
py = '!(' pyc:code ')' -> code
pyc = <python.expr> -> _py(code)
call_rule = name:rulename ('(' name:first (',' name)*:rest ')' -> [first] + rest)?:args -> Call(rulename, args)
leaf_expr = parens | not | literal | str | py
# these need to have a strict order since they do not have a leading char
either = either1:first "|" either1:second -> [_OR, first] + second
either1 = leaf_expr | maybe_repeat | repeat | bind
bind = (leaf_expr | maybe_repeat | repeat):inner ':' name:name -> [_BIND, name, inner]
maybe_repeat = leaf_expr:inner "+" -> [_MAYBE_REPEAT, inner]
repeat = leaf_expr:inner "*" -> [_REPEAT, inner]
'''


_PYTHON_GRAMMAR = r'''
expr = dict | tuple | list | str | ref
dict = "{" (expr ":" expr ","?)* "}"
set = "{" expr ","? "}"
tuple = "(" expr ","? ")"
list = "[" expr ","? "]"
str = ('u' | 'r' | 'b')? (str_1s | str_3s | str_1d | str_3d)
strgen :quote = quote (('\\' quote) | (~quote .))
str_1s = strgen('\'')
str_3s = strgen('\'\'\'')
str_1d = strgen('"')
str_3d = strgen('"""')
'''


class Rule(object):
    '''
    A rule that can be included in a grammar.

    name -- the name by which this rule can be called from other rules
    args -- a sequence of matching expressions applied to
            input to determine if this rule matches
            (rule names may be overloaded, in which case
            they are tried in the order they occur in the
            grammar)
    expr -- the matching expression sequence that forms the
            body of the rule
    '''
    def __init__(self, name, args, expr):
        self.name, self.args, self.expr = name, args, expr


# ( 'a' | 'b'*) ?  =>  [MAYBE, OR, 'a', ANY, 'b']

# MAYBE - switch result to None, stop error
# OR - if LHS hits error, stop error and go to RHS
# ANY - allocate list; keep appending match to list until error


if __name__ == "__main__":
    def chk(rule, src, result, pyglobals=None):
        p = Parser(Grammar({'test': rule}, pyglobals or {}), 'test')
        assert p.parse(src) == result
    chk(['aaa'], 'aaa', 'aaa')
    chk([_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([_MAYBE_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([_MAYBE_REPEAT, 'a'], '', [])
    chk([_OR, 'a', 'b'], 'a', 'a')
    chk([_OR, 'a', 'b'], 'b', 'b')
    chk([_LITERAL, _REPEAT, 'a'], 'a' * 8, 'a' * 8)
    chk([_NOT, 'a', 'b'], 'b', 'b')
    chk([_py('1')], '', 1)
    chk([_BIND, 'foo', _py('1'), _py('foo')], '', 1)
    chk([_BIND, 'foo', _py('1'), [_py('bar')], {'bar': 'foo'}], '', 1)
    chk([_NOT, _ANYTHING], '', None)
    try:
        chk([_NOT, _ANYTHING], 'a', None)
        assert False, "not anything excepted non empty input"
    except Exception:
        pass # good
    # check that OR tries the options in the correct order
    chk([_OR, ['a', _BIND, 'r', _py('1')],
              [_ANYTHING, _BIND, 'r', _py('2')],
              _py('r')], 'a', 1)
    print("GOOD")
