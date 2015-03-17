assert(dn4('localhost') == '127.0.0.1')
assert(dn4('127.0.0.1') == '127.0.0.1')
assert(dn6('::1') == '::1')
assert(dn6('localhost') == '::1')
