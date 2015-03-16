-- This test evaluate that reference counting on shared CPP objects works properly
a = ip({})
assert(a:__cpp_ref_count() == 1)
assert(a:__cpp_auxref_count() == nil)

b = IP / TCP
c = b:tcp()
assert(c:__cpp_ref_count() == 1)
assert(b:__cpp_ref_count() == 2)
assert(c:__cpp_auxref_count() == 2)

d = b:ip()
assert(c:__cpp_ref_count() == 1)
assert(d:__cpp_ref_count() == 1)
assert(b:__cpp_ref_count() == 3)
assert(c:__cpp_auxref_count() == 3)

d = nil
collectgarbage()
collectgarbage()
assert(c:__cpp_ref_count() == 1)
assert(b:__cpp_ref_count() == 2)
assert(c:__cpp_auxref_count() == 2)

