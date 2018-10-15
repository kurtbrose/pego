from .compiler import compile_rules

class Grammar(object):
    '''
    A grammar, generated from an input.
    '''
    # rules = attr.ib()
    #TODO: switch rules to labelled offsets in opcodes
    # opcodes = attr.ib()  # big list of opcodes
    # pyglobals = attr.ib()  # python variables to expose to eval expressions
    def __init__(self, rules, pyglobals):
        self.rules, self.symbols = compile_rules(rules)
        self.pyglobals = pyglobals

    def from_text(cls, text, pyglobals=None):
        '''
        parse ASTs from text and construct a Grammar
        '''
        return cls(AST_GRAMMAR.parse(text), pyglobals=pyglobals or {})


# TODO: is this still relevant?
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
