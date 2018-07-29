
# MODIFIERS -- attach to another expression
# these are arbitrarily recursive
# ? + * ~ <> |

# TERMINALS -- these can be immediately evaluated and produce error or match
# ! '' : ->

# COMPILED OUT -- these modify the structure of the compiled rules, but are gone by eval
# () =


# a rule is a sequence of objects for the convenience of the evaluator:
# [_MAYBE, 'a']  =>  'a'?
# [_EITHER, 'a', 'b']  =>  'a' | 'b'

_Match = attr.make_class('_Match', ['rule', 'start', 'end'], frozen=True)
_Not = attr.make_class('_Not', ['rule'], frozen=True)  # ~
_Bind = attr.make_class('_Bind', ['rule'], frozen=True)  # :
_MAYBE = object()  # ?
_EITHER = object()  # |


@attr.s(frozen=True)
class Grammar(object):
    '''
    A grammar, generated from an input.
    '''
    rules = attr.ib()

    def from_text(cls, text):
        '''
        parse ASTs from text and construct a Grammar
        '''
        return cls(AST_GRAMMAR.parse(text))

    def parse(self, source, rule_name):
        cur_rule = self.rules[rule_name]
        pos = 0
        # evaluate, one rule at a time
        rule_stack = []
        match_stack = []
        err = False
        # stack keeps track of matched rules
        # algorithm proceeds as follows:
        # 1- try to match current rule
        # 2- if failed, back up and find a peer rule
        #    2A - if this stack unwind gets to the root, raise a good exception
        # 3- 
        while pos != len(source):
            if type(cur_rule) is str:
                if source[pos:pos + len(cur_rule)] == cur_rule:
                    match = cur_rule
                    pos += len(cur_rule)
                else:
                    err = True
            elif type(cur_rule) in (_Not, _Maybe, _Repeat, _MaybeRepeat):
                rule_stack.append(cur_rule)
                # check match_stack / rule_stack
                continue

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
