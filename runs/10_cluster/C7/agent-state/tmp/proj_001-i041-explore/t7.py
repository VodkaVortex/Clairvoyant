import re
def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*&]*\**([A-Za-z_][A-Za-z0-9_]*)\s*\(')
tests = [
 "static void foo(void)",
 "static struct sk_buff * foo(void)",
 "static inline int bar(struct x *y)",
 "void baz(unsigned long data)",
 "static void qux(unsigned long data)",
]
for t in tests:
    m = def_re.match(t)
    print(repr(t), '->', repr(m.group(1)) if m else None)
