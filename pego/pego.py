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
_opc("IF", "cond then SKIP else ... -- cond passes -> then; cond error -> else")
#_opc("SKIP", "a b -- skip a and go straight to b")
# SKIP is needed for IF -- it allows then-branch to "jump over" else branch
# in case cond was true, without throwing away the result of then-branch
# (that is, and trap-codes "above" the IF should see the result of the
# then-branch as its result)
_opc("SRC_POP", "pops a source off the source-stack after next opcode returns")
_opc("CALL", "call another rule")
_opc("ERR", "means an error is being thrown")
#_opc("PASS", "noop; convenient sometimes to give a landing point for SKIP")
_opc("MATCH", "a b -- if result of b does not match result of a, error")

_STACK_OPCODES = (
    _NOT, _MAYBE, _REPEAT, _MAYBE_REPEAT, _LITERAL, _OR, _BIND, _IF, _MATCH)


_opc("PENDING", "marker when more execution required")


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


_opc("NO_SCOPE_VAL", "marker for no value bound to name")


class _LinearizedScope(object):
    '''
    A scope that can bind values to names, which also
    keeps track of the position at which the variables
    were bound, allowing it to rewind back to an earlier state
    '''
    def __init__(self):
        self.name_val_map = {}
        self.name_oldval_pos_list = []

    def set(self, name, val, src_pos):
        '''
        set name to val, report current position in case
        later rewind
        '''
        self.name_oldval_pos_list.append(name)
        self.name_oldval_pos_list.append(self.name_val_map.get(name, _NO_SCOPE_VAL))
        self.name_oldval_pos_list.append(src_pos)
        self.name_val_map[name] = val

    def get(self, name):
        '''
        get the last value bound to name
        '''
        return self.name_val_map[name]

    def rewind(self, src_pos):
        '''
        undo all assignments that came after src_pos
        '''
        while self.name_oldval_pos_list and self.name_oldval_pos_list[-1] > src_pos:
            self.name_oldval_pos_list.pop()  # done with src_pos
            oldval = self.name_oldval_pos_list.pop()
            name = self.name_oldval_pos_list.pop()
            if oldval is _NO_SCOPE_VAL:
                del self.name_val_map[name]
            else:
                self.name_val_map[name] = oldval


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
        '''
        this parser operates using a stack of blocks
        "block" means the same thing here as in programming language structure:
        it is a sequence of opcodes that should be executed one after the other
        with no flow control (other than halting on errors)

        some opcodes set "traps" as they move along; this is similar
        to a try/except or context manager: the traps will be unwound
        on block exit before moving to the next block up the stack

        if after unwinding all of the traps the result is error,
        then the traps of the next block up should also be unwound
        continuing all the way up to root


        1- SET UP TRAPS -- THIS MAY FIND THAT IT HAS RUN OFF
        2- EVALUATE A SINGLE VALUE
           - MAY BE A CALL
        3- CLEAR TRAPS -- IF A CALL, THIS IS AUTOMATICALLY NOOP

        after each run through the whole loop, the block_pos pointer
        should be left at the next opcode to evaluate
        '''
        # TODO: deterministic UTF-8 encoding of source and rules strings?
        str_source = isinstance(source, basestring)
        cur_block = self.grammar.rules[self.rule_name]
        block_pos = 0  # opcode index of current block
        binds = _LinearizedScope()  # "locals" -- bound names w/in current rule scope
        traps = []  # "try/except" or context management blocks that will be unwrapped in order
        src_pos = 0  # how much of source has been parsed
        result = None
        # evaluate, one rule at a time
        block_stack = []  # stack to push state onto when evaluating a sub-block/rule
        source_stack = []  # stack to push current src + pos onto
        # stack keeps track of matched rules, matched opcodes w/in rule
        end_of_input = (src_pos == len(source))
        done = False  
        is_returning = False  # finished executing a block or value; unwrapping traps
        # is_returning could also be named "result is valid"
        while not done:
            assert block_pos < len(cur_block)
            # 1- SET UP TRAPS
            while block_pos < len(cur_block):
                opcode = cur_block[block_pos]
                if opcode not in _STACK_OPCODES:
                    break
                if opcode in (_REPEAT, _MAYBE_REPEAT):
                    state = []
                elif opcode is _BIND:
                    state = cur_block[block_pos + 1]
                else:
                    state = _PENDING
                traps.append((opcode, block_pos, src_pos, state))
                if opcode is _BIND:
                    block_pos += 1  # advance 1 more since pos + 1 is bind name
                block_pos += 1
            # NOTE: can't tell the difference between traps up to end of block,
            #       versus no more opcodes left
            #else:
            #    # TODO: better exception / forward detection
            #    raise Exception("traps opcodes up to end of block (no value to wrap)")
            # 2- EVALUATE EXACTLY ONE TIP OPCODE THAT GENERATES A RESULT
            # does not advance block_pos -- leaves it pointed at this opcode
            # relies on traps unwrapping code below to advance the block_pos
            if opcode is _ANYTHING:
                if src_pos < len(source):
                    result = source[src_pos]
                    src_pos += 1
                else:
                    result = _ERR; print "111111111"
                is_returning = True
            elif type(opcode) is str:  # string literal match
                if str_source and source[src_pos:src_pos + len(opcode)] == opcode:
                    result = opcode
                    src_pos += len(opcode)
                elif not str_source and source[src_pos] == opcode:
                    # sequence matching
                    result = opcode
                    src_pos += 1
                else:
                    result = _ERR; print "222222222"
                is_returning = True
            elif type(opcode) is types.CodeType:  # eval python expression
                try:
                    result = eval(opcode, self.grammar.pyglobals, binds.name_val_map)
                except Exception as e:
                    # import traceback; traceback.print_exc()
                    result = _ERR; print "33333333333"
                print "EVAL RESULT", result
                is_returning = True
            elif type(opcode) is list:
                # internal flow control w/in a rule; same scope
                block_stack.append((cur_block, block_pos + 1, binds, traps))
                # set block_pos to -1 so increment will put it to 0
                cur_block, block_pos, traps = opcode, -1, []
                is_returning = False  # no value to return, need to eval child block
            elif opcode is _CALL:  # calling another rule
                # [ ..., _CALL, [list-of-arg-names], [target-rule], ...]
                # 0- push the current source + pos onto the source-stack
                source_stack.append((source, src_pos))
                # print(source_stack)
                # 1- set the source to be the arg-list
                # (it is the job of the called rule to pop the arg list off the source stack)
                source = [binds.get(name) for name in cur_block[block_pos + 1]]
                src_pos = 0
                # 3- push the current block onto the stack, create a new bind scope
                block_stack.append((cur_block, block_pos + 3, binds, traps))
                cur_block = cur_block[block_pos + 2]
                print "CALL", cur_block[:4]
                block_pos, binds, traps = -1, _LinearizedScope(), []
            elif opcode is _SRC_POP:
                # print cur_block, block_pos, traps, source, src_pos
                # import pdb; pdb.set_trace()
                if result is not _ERR:
                    source, src_pos = source_stack.pop()
                is_returning = True
                # don't really have a value to return, but need to get block_stack
                # to pop..... consider changing is_returning to end_of_block
            elif opcode is _SKIP:
                # [ ..., SKIP, a, b, ...]  immediately jump to b
                assert len(cur_block) >= block_pos + 2
                block_pos += 1  # skip next opcode
            elif opcode is _ERR:
                result = _ERR; print "4444444444"
                # import pdb; pdb.set_trace()
                is_returning = True
            elif opcode is _PASS:
                is_returning = True
            # print "RESULT", opcode, block_pos, result, is_returning
            block_pos += 1
            # print len(block_stack), block_pos, opcode

            # 3- UNWRAP TRAPS
            end_of_input = (src_pos == len(source))
            while is_returning:
                '''
                unwrap once to handle the value returned by the evaluation above,
                then continue unwrapping as long as the current block has reached its end
                '''
                while traps:
                    '''
                    this loop is responsible for unwrapping the "try/except" traps
                    that have been set in executing the current block
                    '''
                    trapcode, trap_pos, last_src_pos, state = traps.pop()
                    if trapcode is _BIND:
                        # [ ..., _BIND, name, expression, ... ]
                        if result is not _ERR:
                            binds.set(state, result, src_pos)
                    elif trapcode is _NOT:
                        if result is _ERR:
                            result = None
                            src_pos = last_src_pos
                            break
                        else:
                            result = _ERR; print "555555"
                    elif trapcode is _MAYBE:
                        if result is _ERR:
                            src_pos = last_src_pos
                            result = None
                        break
                    elif trapcode in (_REPEAT, _MAYBE_REPEAT):
                        if result is _ERR:
                            if len(state) > 0 or trapcode is _MAYBE_REPEAT:
                                result = state
                                src_pos = last_src_pos
                                # NOTE: rewind src_pos back to last complete match
                                break
                        elif end_of_input:
                            state.append(result)
                            result = state
                        else:
                            state.append(result)
                            traps.append((trapcode, trap_pos, src_pos, state))
                            block_pos = trap_pos + 1  # rewind block_pos to replay
                            break
                    elif trapcode is _LITERAL:
                        if result is not _ERR:
                            result = source[last_src_pos:src_pos]
                    elif trapcode is _OR:
                        # [ ..., _OR, branch1, branch2, ... ]
                        if result is _ERR:
                            # try the other branch from the same position
                            # (NOTE: block_pos will advance, but OR is no
                            #  longer on the stack so next error will not be caught)
                            src_pos = last_src_pos
                            break
                        else:
                            # if first branch worked, increment block_pos
                            # to skip over second branch
                            block_pos += 1
                    elif trapcode is _IF:
                        # [ ..., _IF, cond, then, else, ...]
                        if state is _PENDING:  # eval cond
                            if result is _ERR:  # else-branch
                                src_pos = last_src_pos  # roll-back cond-eval
                                block_pos = trap_pos + 3  # go-to else branch
                                break
                            else:  # if-branch
                                traps.append((trapcode, trap_pos, src_pos, True))
                                break
                        else:  # if-branch finishing
                            block_pos = trap_pos + 4  # skip else-branch
                    elif trapcode is _MATCH:
                        #import pdb; pdb.set_trace()
                        # [..., MATCH, a, b, ... ]
                        if state is _PENDING:  # a-branch
                            if result is not _ERR:
                                state = result
                                traps.append((trapcode, trap_pos, src_pos, state))
                        else:  # b-branch
                            if state != result:
                                result = _ERR; print "666666666"
                    else:
                        assert False, "unrecognized trap opcode"
                binds.rewind(src_pos)  # throw away any bindings that we have rewound back off of
                # fully unwrapped current traps without any instructions to resume execution
                # iterate to the next step: either (1) advance cur_pos, or (2) pop the stack
                is_returning = (block_pos == len(cur_block))
                if is_returning:
                    # print "RETURNED", result
                    if not block_stack:
                        if end_of_input and not source_stack:
                            done = True
                            break  # GOOD, end of rules, end of input
                        else:
                            raise ValueError("extra input: {}".format(repr(source[src_pos:])))
                    cur_block, block_pos, binds, traps = block_stack.pop()
                    print "RETURNING", result
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


def test():
    def chk(rule, src, result, pyglobals=None):
        assert pyglobals is None or type(pyglobals) is dict
        p = Parser(Grammar({'test': rule}, pyglobals or {}), 'test')
        r = p.parse(src)
        assert r == result, r
        print rule, src, r, "GOOD"
    def err_chk(rule, src, pyglobals=None):
        assert pyglobals is None or type(pyglobals) is dict
        p = Parser(Grammar({'test': rule}, pyglobals or {}), 'test')
        try:
            p.parse(src)
            raise Exception('negative test case failed')
        except Exception:
            pass
    chk(['aaa'], 'aaa', 'aaa')
    chk([['aaa']], 'aaa', 'aaa')
    chk([[['aaa']]], 'aaa', 'aaa')
    chk([_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([_REPEAT, ['a']], 'a' * 8, ['a'] * 8)
    err_chk([_REPEAT, 'a', _REPEAT, 'b'], 'bbb')  # repeat requires at least one 'a'
    chk([_MAYBE_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([_MAYBE_REPEAT, ['a']], '', [])
    chk([_MAYBE_REPEAT, 'a', _REPEAT, 'b'], 'bbb', ['b'] * 3)  # maybe repeat is okay with 0 a's
    a_then_b = [_REPEAT, [_REPEAT, 'a', 'b']]
    chk(a_then_b, 'aaaaababaaaab', ['b', 'b', 'b'])
    err_chk(a_then_b, 'aaa')
    err_chk(a_then_b, '')
    chk([_OR, ['a'], ['b']], 'a', 'a')
    chk([_OR, ['a'], ['b']], 'b', 'b')
    err_chk([_OR, ['a'], ['b']], 'c')
    chk([_OR, 'a', 'b', 'c'], 'ac', 'c')
    chk([_OR, 'a', 'b', 'c'], 'bc', 'c')
    err_chk([_OR, [_BIND, 'first', 'a', 'bad'], [_BIND, 'second', 'a', 'good'], _py('first')], 'agood')
    # check that _BIND to 'first' is properly unwound
    chk([_LITERAL, _REPEAT, 'a'], 'a' * 8, 'a' * 8)
    chk([_NOT, 'a', 'b'], 'b', 'b')
    chk([_py('1')], '', 1)
    # err_chk([_py('undefined')], '')  # TODO: dont swallow undefined errors
    chk([_BIND, 'foo', _py('1'), _py('foo')], '', 1)
    # chk([_BIND, 'foo', _py('1'), [_py('bar')], {'bar': 'foo'}], '', 1)
    # TODO: fix this test to conform to correct rule calls once I figure out what that looks like....
    chk([_NOT, _ANYTHING], '', None)
    chk([_NOT, _ANYTHING], [], None)
    err_chk([_NOT, _ANYTHING], 'a')
    chk([_OR, ['a', 'b'], ['a', 'c']], 'ac', 'c')
    # check that OR tries the options in the correct order
    chk([_OR, ['a', _BIND, 'r', _py('1')],
              [_ANYTHING, _BIND, 'r', _py('2')],
              _py('r')], 'a', 1)
    # basic check of IF (building towards RULE calls)
    chk([_IF, 'a', 'b', 'c', 'd'], 'abd', 'd')
    chk([_IF, 'a', 'b', 'c', 'd'], 'cd', 'd')
    # check rules calling each other
    no_args_one_a_rule = [_IF, [_NOT, _ANYTHING, _SRC_POP], 'a', [_SRC_POP, _ERR]]
    #                     ^if args ^args=empty       body='a'^   ^skip error ^arg-mismatch-error
    chk([_CALL, [], no_args_one_a_rule], 'a', 'a')
    err_chk([_CALL, [], no_args_one_a_rule], 'b')  # error from rule body not matching
    err_chk([_BIND, 'foo', _py('1'), _CALL, ['foo'], no_args_one_a_rule], 'a')  # error from arg mismatch
    # match tests
    chk([_MATCH, 'a', 'a'], 'aa', 'a')
    chk([_MATCH, 'a', _py('"a"')], 'a', 'a')
    err_chk([_MATCH, 'a', 'b'], 'ab')
    err_chk([_MATCH, 'a', _py('"b"')], 'a')
    # rule with args
    sum_rule = [
        _IF, [_BIND, 'a', _ANYTHING, _BIND, 'b', _ANYTHING, _NOT, _ANYTHING, _SRC_POP],
        [_py('a + b')], [_SRC_POP, _ERR]]
    sum_grammar = [_BIND, 'a', _ANYTHING, _BIND, 'b', _ANYTHING,
                   _CALL, ['a', 'b'], sum_rule]
    chk(sum_grammar, [1, 1], 2)  # called w/ correct args, sum_rule works
    err_chk([_CALL, [], sum_rule], '')  # missing arg fails
    # two rules accepting different args w/ cascade behavior
    a1_b2_rule = [
        _IF, ['a', _NOT, _ANYTHING, _SRC_POP],
        _py('1'),
        [
            _IF, ['b', _NOT, _ANYTHING, _SRC_POP],
            _py('2'), [_SRC_POP, _ERR]
        ],
    ]
    a1_b2_grammar = [_BIND, 'p', _ANYTHING, _CALL, ['p'], a1_b2_rule]
    '''
    chk(a1_b2_grammar, 'a', 1)
    chk(a1_b2_grammar, 'b', 2)
    # test factorial rule
    end_of_args = [_NOT, _ANYTHING, _SRC_POP]
    one_arg_0 = [_MATCH, _py('0'), _ANYTHING] + end_of_args
    one_arg_anything = [_BIND, 'n', _ANYTHING] + end_of_args
    factorial = []
    factorial.extend(
        [_IF, one_arg_0, _py('1'),
            [_IF, one_arg_anything,
                [_BIND, 'recurse_arg', _py('n - 1'),
                 _BIND, 'm', [_CALL, ['recurse_arg'], factorial],
                 _py('n * m')],
                [_SRC_POP, _ERR]]])
    fact_grammar = [_BIND, 'n', _ANYTHING, _CALL, ['n'], factorial]
    chk(fact_grammar, [0], 1)
    chk(fact_grammar, [1], 1)
    err_chk([_BIND, 'n', _py('1'),
             _CALL, ['n'],  # check that one_arg_0 doesn't accept 1
                [_IF, one_arg_0, _py('1'), [_SRC_POP, _ERR]]], '')
    chk(fact_grammar, [2], 2)
    #chk(fact_grammar, [3], 6)
    #chk(fact_grammar, [4], 24)
    '''
    print("GOOD")


if __name__ == "__main__":
    test()
