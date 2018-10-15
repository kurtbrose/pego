from .vm import (
    Parser, REPEAT, MAYBE_REPEAT, OR, BIND, NOT, ANYTHING, IF, SRC_POP,
    ERR, MATCH, CALL, LITERAL)
from .pego import Grammar
from .grammars import _BOOTSTRAP1_GRAMMAR

# ( 'a' | 'b'*) ?  =>  [MAYBE, OR, 'a', ANY, 'b']

# MAYBE - switch result to None, stop error
# OR - if LHS hits error, stop error and go to RHS
# ANY - allocate list; keep appending match to list until error

_py = lambda code: compile(code, '<string>', 'eval')


def test_opcodes():
    def chk(rule, src, result, pyglobals=None):
        assert pyglobals is None or type(pyglobals) is dict
        p = Parser(Grammar({'test': rule}, pyglobals or {}), 'test')
        r = p.parse(src)
        assert r == result, r
        # print rule, src, r, "GOOD"
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
    chk([REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([REPEAT, ['a']], 'a' * 8, ['a'] * 8)
    err_chk([REPEAT, 'a', REPEAT, 'b'], 'bbb')  # repeat requires at least one 'a'
    chk([MAYBE_REPEAT, 'a'], 'a' * 8, ['a'] * 8)
    chk([MAYBE_REPEAT, ['a']], '', [])
    chk([MAYBE_REPEAT, 'a', REPEAT, 'b'], 'bbb', ['b'] * 3)  # maybe repeat is okay with 0 a's
    a_then_b = [REPEAT, [REPEAT, 'a', 'b']]
    chk(a_then_b, 'aaaaababaaaab', ['b', 'b', 'b'])
    err_chk(a_then_b, 'aaa')
    err_chk(a_then_b, '')
    chk([OR, ['a'], ['b']], 'a', 'a')
    chk([OR, 'a', 'b'], 'b', 'b')
    err_chk([OR, ['a'], ['b']], 'c')
    chk([OR, 'a', 'b', 'c'], 'ac', 'c')
    chk([OR, 'a', 'b', 'c'], 'bc', 'c')
    err_chk([OR, [BIND, 'first', 'a', 'bad'], [BIND, 'second', 'a', 'good'], _py('first')], 'agood')
    # check that BIND to 'first' is properly unwound
    chk([LITERAL, REPEAT, 'a'], 'a' * 8, 'a' * 8)
    chk([NOT, 'a', 'b'], 'b', 'b')
    chk([_py('1')], '', 1)
    # err_chk([_py('undefined')], '')  # TODO: dont swallow undefined errors
    chk([BIND, 'foo', _py('1'), _py('foo')], '', 1)
    # chk([BIND, 'foo', _py('1'), [_py('bar')], {'bar': 'foo'}], '', 1)
    # TODO: fix this test to conform to correct rule calls once I figure out what that looks like....
    chk([NOT, ANYTHING], '', None)
    chk([NOT, ANYTHING], [], None)
    err_chk([NOT, ANYTHING], 'a')
    chk([OR, ['a', 'b'], ['a', 'c']], 'ac', 'c')
    # check that OR tries the options in the correct order
    chk([OR, ['a', BIND, 'r', _py('1')],
              [ANYTHING, BIND, 'r', _py('2')],
              _py('r')], 'a', 1)
    # basic check of IF (building towards RULE calls)
    chk([IF, 'a', 'b', 'c', 'd'], 'abd', 'd')
    chk([IF, 'a', 'b', 'c', 'd'], 'cd', 'd')
    # check rules calling each other
    no_args_one_a_rule = [IF, [NOT, ANYTHING, SRC_POP], 'a', [SRC_POP, ERR]]
    #                     ^if args ^args=empty       body='a'^   ^skip error ^arg-mismatch-error
    chk([CALL, [], no_args_one_a_rule], 'a', 'a')
    err_chk([CALL, [], no_args_one_a_rule], 'b')  # error from rule body not matching
    err_chk([BIND, 'foo', _py('1'), CALL, ['foo'], no_args_one_a_rule], 'a')  # error from arg mismatch
    # match tests
    chk([MATCH, 'a', 'a'], 'aa', 'a')
    chk([MATCH, 'a', _py('"a"')], 'a', 'a')
    chk([MATCH, _py('"a"'), 'a'], 'a', 'a')
    chk([MATCH, _py('0'), ANYTHING], [0], 0)
    chk([MATCH, ANYTHING, _py('0')], [0], 0)
    err_chk([MATCH, 'a', 'b'], 'ab')
    err_chk([MATCH, 'a', _py('"b"')], 'a')
    err_chk([MATCH, _py('0'), ANYTHING], [1])
    # rule with args
    sum_rule = [
        IF, [BIND, 'a', ANYTHING, BIND, 'b', ANYTHING, NOT, ANYTHING, SRC_POP],
        [_py('a + b')], [SRC_POP, ERR]]
    sum_grammar = [BIND, 'a', ANYTHING, BIND, 'b', ANYTHING,
                   CALL, ['a', 'b'], sum_rule]
    chk(sum_grammar, [1, 1], 2)  # called w/ correct args, sum_rule works
    chk(sum_grammar, [1, 2], 3)
    err_chk([CALL, [], sum_rule], '')  # missing arg fails
    # rule applying other rule in args
    a_rule = [IF, ['a', NOT, ANYTHING, SRC_POP], _py('"a"'), [SRC_POP, ERR]]
    aaa_rule = [
        IF, [
            BIND, 'one', ANYTHING, CALL, ['one'], a_rule,
            BIND, 'two', ANYTHING, CALL, ['two'], a_rule,
            BIND, 'three', ANYTHING, CALL, ['three'], a_rule,
            NOT, ANYTHING, SRC_POP],
        _py('"hello"'),
        [SRC_POP, ERR]
    ]
    aaa_grammar = [BIND, 'c', ANYTHING, CALL, ['c', 'c', 'c'], aaa_rule]
    chk([BIND, 'c', ANYTHING, CALL, ['c'], a_rule], 'a', 'a')
    chk(aaa_grammar, 'a', 'hello')
    err_chk(aaa_grammar, 'b')
    # two rules accepting different args w/ cascade behavior
    a1_b2_rule = [
        IF, ['a', NOT, ANYTHING, SRC_POP],
        _py('1'),
        [
            IF, ['b', NOT, ANYTHING, SRC_POP],
            _py('2'), [SRC_POP, ERR]
        ],
    ]
    a1_b2_grammar = [BIND, 'p', ANYTHING, CALL, ['p'], a1_b2_rule]
    chk(a1_b2_grammar, 'a', 1)
    chk(a1_b2_grammar, 'b', 2)
    # test factorial rule
    end_of_args = [NOT, ANYTHING, SRC_POP]
    one_arg_0 = [MATCH, _py('0'), ANYTHING] + end_of_args
    one_arg_anything = [BIND, 'n', ANYTHING] + end_of_args
    factorial = []
    factorial.extend(
        [IF, one_arg_0, _py('1'),
            [IF, one_arg_anything,
                [BIND, 'recurse_arg', _py('n - 1'),
                 BIND, 'm', [CALL, ['recurse_arg'], factorial],
                 _py('n * m')],
                [SRC_POP, ERR]]])
    fact_grammar = [BIND, 'n', ANYTHING, CALL, ['n'], factorial]
    chk(fact_grammar, [0], 1)
    chk(fact_grammar, [1], 1)
    err_chk([BIND, 'n', _py('1'),
             CALL, ['n'],  # check that one_arg_0 doesn't accept 1
                [IF, one_arg_0, _py('1'), [SRC_POP, ERR]]], '')
    chk([IF, [MATCH, _py('0'), ANYTHING], _py('1'), _py('100')], [0], 1)
    chk([IF, [MATCH, _py('0'), ANYTHING], _py('1'), ANYTHING, _py('100')], ['no-match'], 100)
    chk([BIND, 'n', _py('1'), CALL, ['n'], [  # check that else-branch is executed on arg mis-match
        IF, one_arg_0, _py('2'), _py('3'), SRC_POP]], '', 3)
    chk(fact_grammar, [2], 2)
    chk(fact_grammar, [3], 6)
    chk(fact_grammar, [4], 24)
    # misc chunks to help bootstrapping grammar
    chk([LITERAL, MAYBE_REPEAT, [OR, "\\'", [NOT, "'", ANYTHING]]], "\\'abc", "\\'abc")
    chk([LITERAL, MAYBE_REPEAT, ANYTHING], "abc", "abc")
    chk([LITERAL, MAYBE_REPEAT, ANYTHING], "", "")
    chk([BIND, 'val', "\\'abc", "'", _py('val')], "\\'abc'", "\\'abc")
    chk([BIND, 'val', LITERAL, MAYBE_REPEAT, [OR, "\\'", [NOT, "'", ANYTHING]], "'", _py('val')],
        "\\'abc'", "\\'abc")


def test_bootstrap():
    def chk(rule_name, src, expected):
        parser = Parser(_BOOTSTRAP1_GRAMMAR, rule_name)
        result = parser.parse(src)
        assert result == expected, result

    def chk_str(rule_name):
        'check a rule which should accept a string literal does'
        chk(rule_name, "''", '')
        chk(rule_name, "'abc'", 'abc')
        chk(rule_name, "'\\'abc'", "\\'abc")

    chk_str('str')
    #chk_str('leaf_expr')
    chk_str('expr')

    chk('name', 'bob', 'bob')
