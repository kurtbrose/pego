'''
Provides various grammars.
'''
from .vm import REPEAT, OR, MAYBE, MAYBE_REPEAT, NOT, BIND, LITERAL, ANYTHING
from .pego import Grammar
from .compiler import Ref

_py = lambda code: compile(code, '<string>', 'eval')


'''
A stripped down version of the grammar, used as to compile
the more complete BOOTSTRAP2 grammar
'''
_BOOTSTRAP1_GRAMMAR = Grammar(
    {
        'ws': [REPEAT, OR, ' ',  '\n'],
        'brk': [Ref('ws'), MAYBE, ['#', MAYBE_REPEAT, NOT, '\n', '\n']],
        'grammar': [BIND, 'rules', REPEAT, Ref('rule'), _py('dict(rules)')],
        'rule': [BIND, 'name', BIND, 'name', Ref('name'), '= ',
                 BIND, 'expr', Ref('expr'), _py('(name, expr)')],
        'name': [LITERAL, REPEAT, [NOT, Ref('ws'), ANYTHING]],
        'expr': [BIND, 'body'] + sum(
            [[OR, Ref(rule)] for rule in ('leaf_expr', 'either', 'bind', 'maybe_repeat', 'repeat')],
            []) + [MAYBE, [BIND, 'action', Ref('pyc'), _py('body + [action]')]],
        'parens': ['(', BIND, 'inner', Ref('expr'), ')', _py('inner')],
        'not': ['~', BIND, 'inner', Ref('expr'), _py('[NOT, inner]')],
        'literal': ['<', BIND, 'inner', Ref('expr'), '>', _py('[LITERAL, inner]')],
        'str': ["'", BIND, 'val', LITERAL, MAYBE_REPEAT, [OR, "\\'", [NOT, "'", ANYTHING]], "'", _py('val')],
        'tok': [NOT, ANYTHING],  # TODO: real tok
        'pyc': [NOT, ANYTHING],  # TODO: real pyc
        'py': ['!(', BIND, 'code', Ref('pyc'), ')', _py('code')],
        'call_rule': [
            BIND, 'rulename', Ref('name'), BIND, 'args', MAYBE, [
                '(', BIND, 'first', Ref('name'), BIND, 'rest', MAYBE_REPEAT, [',', Ref('name')], ')'],
            _py('[_CALL, args or [], Ref(rulename)]')],
        'leaf_expr': sum([[OR, Ref(r)] for r in ('parens', 'not', 'literal', 'str')], []) + [Ref('py')],
        'either': [BIND, 'first', Ref('either1'), '|', BIND, 'second',
                   Ref('either1'), _py('[OR, first] + second')],
        'either1': [OR, Ref('leaf_expr'), OR, Ref('maybe_repeat'),
                    OR, Ref('repeat'), Ref('bind')],
        'bind': [BIND, 'inner', [OR, Ref('leaf_expr'), OR, Ref('maybe_repeat'), Ref('repeat')],
                 ':', BIND, 'name', Ref('name'), _py('[BIND, name, inner]')],
        'maybe_repeat': [BIND, 'inner', Ref('leaf_expr'), '+', _py('[MAYBE_REPEAT, inner]')],
        'repeat': [BIND, 'inner', '*', _py('[REPEAT, inner]')]
    },
    {
        'Grammar': Grammar
    }
)


# the complete grammar, expressed using as few symbols as possible
# in order to make the first bootstrap grammar which must be hand
# coded as simple as possible
_BOOTSTRAP2_GRAMMAR = '''
ws = (' ' | '\t' | '\n')
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
not = '~' expr:inner -> [NOT, inner]
literal = '<' expr:inner '>' -> [LITERAL, inner]
str = '\'' <('\\\'' | (~'\'' .))*>:val '\'' -> val
tok = '\"' <('\\\"' | (~'\"' .))*>:val '\"' `token(val)`
py = '!(' pyc:code ')' -> code
pyc = <python.expr> -> _py(code)
call_rule = name:rulename ('(' name:first (',' name)*:rest ')' -> [first] + rest)?:args -> Call(rulename, args)
leaf_expr = parens | not | literal | str | py
# these need to have a strict order since they do not have a leading char
either = either1:first "|" either1:second -> [OR, first] + second
either1 = leaf_expr | maybe_repeat | repeat | bind
bind = (leaf_expr | maybe_repeat | repeat):inner ':' name:name -> [BIND, name, inner]
maybe_repeat = leaf_expr:inner "+" -> [MAYBE_REPEAT, inner]
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