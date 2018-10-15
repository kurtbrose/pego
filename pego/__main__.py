if __name__ != "__main__":
    raise ImportError('imported __main__.py!')

from .test import test_opcodes, test_bootstrap

test_opcodes()
test_bootstrap()
print("GOOD")
