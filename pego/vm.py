'''
The VM module provides a Parser which implements the opcodes.
'''
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
# [MAYBE, 'a']  =>  'a'?
# [OR, 'a', 'b']  =>  'a' | 'b'


class Opcode(object):
    '''Parsing VM Opcodes'''
    def __init__(self, name, description):
        self.name, self.description = name, description

    def __repr__(self):
        return '<' + self.name + '>'

    def __copy__(self): return self
    def __deepcopy__(self, memo): return self


def _opc(name, description):
    globals()[name] = Opcode(name, description)


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
    NOT, MAYBE, REPEAT, MAYBE_REPEAT, LITERAL, OR, BIND, IF, MATCH)


_opc("PENDING", "marker when more execution required")


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
        self.name_oldval_pos_list.append(self.name_val_map.get(name, NO_SCOPE_VAL))
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
            if oldval is NO_SCOPE_VAL:
                del self.name_val_map[name]
            else:
                self.name_val_map[name] = oldval


def _format_opcode(opcode, symbols, recurse=True):
    if type(opcode) is list:
        name = symbols.block_name(opcode)
        if name:
            return '[' + name + ']'
        elif recurse:
            return '[' + ', '.join(_format_opcode(e, symbols, False) for e in opcode) + ']'
        elif opcode:
            return '[...]'
        else:
            return '[]'
    else:
        return repr(opcode)


def _format_block_pos(block, pos, symbols, before=3, after=3):
    '''
    summarize a block by showing the opcodes around its current position
    '''
    if pos <= before:
        prefix = []
        start = 0
    else:
        prefix = ['...']
        start = pos - before
    if pos + after + 1 > len(block):
        end = len(block)
        suffix = []
    else:
        end = pos + after + 1
        suffix = ['...']
    formatted_opcodes = []
    fmt_opc = lambda recurse=True: _format_opcode(opcode, symbols, recurse)
    for i in range(start, end):
        opcode = block[i]
        if i == pos:
            formatted_opcodes.append('*' + fmt_opc(False) + '*')
        else:
            formatted_opcodes.append(fmt_opc())
    return ','.join(prefix + formatted_opcodes + suffix)


def _format_blockstack(block_stack, symbols):
    '''
    format a traceback style output for a block stack
    '''
    stack = []
    indent = 0
    for cur_block, block_pos, binds, traps in block_stack:
        name = symbols.block_name(cur_block)
        cur_line = []
        if name:
            indent = 0
            cur_line.append(name)
        else:
            indent += 3
        opcodes = _format_block_pos(cur_block, block_pos, symbols)
        cur_line.append(' ' * indent)
        cur_line.append(opcodes)
        stack.append(''.join(cur_line))
    return '\n'.join(stack)


def _format_source(src, pos):
    if type(src) is list:
        # TODO: can probably do better than this, but mostly
        # concerned with strings for now
        src = src[pos:]
        if len(list) <= 3:
            return repr(list)
        return '...' + repr(list[-3:])
    else:
        assert isinstance(src, basestring)
        marker = ' ' * min(pos, 11) + '^'
        if pos <= 11:
            line_prefix = src[:pos]
        else:
            line_prefix = '...' + src[pos - 8:pos]
        if len(src) <= pos + 11:
            line_suffix = src[pos:]
        else:
            line_suffix = src[pos:pos + 8] + '...'
        line = line_prefix + line_suffix
        pos_detail = 'at byte {} of {} (line {})'.format(
            pos + 1, len(src), src[:pos].count('\n') + 1)
        return '{}\n{}\n{}'.format(pos_detail, line, marker)


class ParseError(Exception):
    def __init__(self, message, block_stack, symbols, src, pos):
        self.message, self.block_stack, self.symbols = message, block_stack, symbols
        self.args = '{}\n{}\n{}'.format(
            message,
            _format_source(src, pos),
            _format_blockstack(block_stack, symbols),
        ),


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
            if not block_pos < len(cur_block):
                raise ParseError(
                    'ran off end of block',
                    block_stack,
                    self.grammar.symbols,
                    source,
                    src_pos)
            # 1- SET UP TRAPS
            while block_pos < len(cur_block):
                opcode = cur_block[block_pos]
                if opcode not in _STACK_OPCODES:
                    break
                if opcode in (REPEAT, MAYBE_REPEAT):
                    state = []
                elif opcode is BIND:
                    state = cur_block[block_pos + 1]
                else:
                    state = PENDING
                traps.append((opcode, block_pos, src_pos, state))
                if opcode is BIND:
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
            if opcode is ANYTHING:
                if src_pos < len(source):
                    result = source[src_pos]
                    src_pos += 1
                else:
                    result = ERR
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
                    result = ERR
                is_returning = True
            elif type(opcode) is types.CodeType:  # eval python expression
                try:
                    result = eval(opcode, self.grammar.pyglobals, binds.name_val_map)
                except Exception as e:
                    # import traceback; traceback.print_exc()
                    result = ERR
                is_returning = True
            elif type(opcode) is list:
                # internal flow control w/in a rule; same scope
                block_stack.append((cur_block, block_pos + 1, binds, traps))
                # set block_pos to -1 so increment will put it to 0
                cur_block, block_pos, traps = opcode, -1, []
                is_returning = False  # no value to return, need to eval child block
            elif opcode is CALL:  # calling another rule
                # [ ..., CALL, [list-of-arg-names], [target-rule], ...]
                # 0- push the current source + pos onto the source-stack
                source_stack.append((source, src_pos))
                # print(source_stack)
                # 1- set the source to be the arg-list
                # (it is the job of the called rule to pop the arg list off the source stack)
                source = [binds.get(name) for name in cur_block[block_pos + 1]]
                str_source = False
                src_pos = 0
                # 3- push the current block onto the stack, create a new bind scope
                block_stack.append((cur_block, block_pos + 3, binds, traps))
                cur_block = cur_block[block_pos + 2]
                block_pos, binds, traps = -1, _LinearizedScope(), []
            elif opcode is SRC_POP:
                # print cur_block, block_pos, traps, source, src_pos
                # import pdb; pdb.set_trace()
                if result is not ERR:
                    source, src_pos = source_stack.pop()
                    str_source = type(source) is not list
                is_returning = True
                # don't really have a value to return, but need to get block_stack
                # to pop..... consider changing is_returning to end_of_block
            elif opcode is ERR:
                result = ERR
                # import pdb; pdb.set_trace()
                is_returning = True
            '''
            elif opcode is _PASS:
                is_returning = True
            elif opcode is _SKIP:
                # [ ..., SKIP, a, b, ...]  immediately jump to b
                assert len(cur_block) >= block_pos + 2
                block_pos += 1  # skip next opcode
            '''
            # print "RESULT", opcode, block_pos, result, is_returning
            block_pos += 1
            # print len(block_stack), block_pos, opcode

            # 3- UNWRAP TRAPS
            end_of_input = (src_pos == len(source))
            while is_returning:
                '''
                unwrap once to handle the value returned by the evaluation above,
                then continue unwrapping as long as the current block has reached its end
                or result is ERR
                '''
                while traps:
                    '''
                    this loop is responsible for unwrapping the "try/except" traps
                    that have been set in executing the current block
                    '''
                    trapcode, trap_pos, last_src_pos, state = traps.pop()
                    if trapcode is BIND:
                        # [ ..., BIND, name, expression, ... ]
                        if result is not ERR:
                            binds.set(state, result, src_pos)
                    elif trapcode is NOT:
                        if result is ERR:
                            result = None
                            src_pos = last_src_pos
                            break
                        else:
                            result = ERR
                    elif trapcode is MAYBE:
                        if result is ERR:
                            src_pos = last_src_pos
                            result = None
                        break
                    elif trapcode in (REPEAT, MAYBE_REPEAT):
                        if result is ERR:
                            if len(state) > 0 or trapcode is MAYBE_REPEAT:
                                result = state
                                src_pos = last_src_pos
                                # NOTE: rewind src_pos back to last complete match
                        elif end_of_input:
                            state.append(result)
                            result = state
                        else:
                            state.append(result)
                            traps.append((trapcode, trap_pos, src_pos, state))
                            block_pos = trap_pos + 1  # rewind block_pos to replay
                            break
                    elif trapcode is LITERAL:
                        if result is not ERR:
                            result = source[last_src_pos:src_pos]
                    elif trapcode is OR:
                        # [ ..., OR, branch1, branch2, ... ]
                        if result is ERR:
                            # try the other branch from the same position
                            # (NOTE: block_pos will advance, but OR is no
                            #  longer on the stack so next error will not be caught)
                            src_pos = last_src_pos
                            result = None  # stop error propagation
                            break
                        else:
                            # if first branch worked, increment block_pos
                            # to skip over second branch
                            block_pos += 1
                    elif trapcode is IF:
                        # [ ..., IF, cond, then, else, ...]
                        if state is PENDING:  # eval cond
                            if result is ERR:  # else-branch
                                src_pos = last_src_pos  # roll-back cond-eval
                                block_pos = trap_pos + 3  # go-to else branch
                                result = None  # stop error propagation
                                break
                            else:  # if-branch
                                traps.append((trapcode, trap_pos, src_pos, True))
                                break
                        else:  # if-branch finishing
                            block_pos = trap_pos + 4  # skip else-branch
                    elif trapcode is MATCH:
                        #import pdb; pdb.set_trace()
                        # [..., MATCH, a, b, ... ]
                        if state is PENDING:  # a-branch
                            if result is not ERR:
                                state = result
                                traps.append((trapcode, trap_pos, src_pos, state))
                                break
                        else:  # b-branch
                            if state != result:
                                result = ERR
                    else:
                        assert False, "unrecognized trap opcode"
                binds.rewind(src_pos)  # throw away any bindings that we have rewound back off of
                # fully unwrapped current traps without any instructions to resume execution
                # iterate to the next step: either (1) advance cur_pos, or (2) pop the stack
                is_returning = (block_pos == len(cur_block) or result is ERR)
                if is_returning:
                    # print "RETURNED", result
                    if not block_stack:
                        if end_of_input and not source_stack:
                            done = True
                            break  # GOOD, end of rules, end of input
                        else:
                            raise ValueError("extra input: {}".format(repr(source[src_pos:])))
                    cur_block, block_pos, binds, traps = block_stack.pop()
        if result is ERR:
            raise Exception('oh no!')  # raise a super-good exception
        return result

        # GOOD condition is rule stack empty, at last byte
