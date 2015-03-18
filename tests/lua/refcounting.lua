--
-- Tracebox -- A middlebox detection tool
--
--  Copyright 2013-2015 by its authors.
--  Some rights reserved. See LICENSE, AUTHORS.
--

-- This test evaluate that reference counting on shared CPP  works properly

function gc()
	collectgarbage()
	collectgarbage()
end

gc()

objects = __cpp_object_count()
function count_obj(x)
	y = __cpp_object_count() - objects
	if y ~= x then
		print('Expected ' .. x .. ' got ' .. y .. ' instead')
		print(debug.traceback())
	end
	assert(y == x)
end

a = IP.new({})
gc()
assert(a:__cpp_ref_count() == 1)
assert(a:__cpp_ownerref_count() == nil)
count_obj(1)

b = IP.new{} / TCP.new{}
gc()
count_obj(2)
assert(b:__cpp_ref_count() == 1)

c = b:tcp()
assert(c:__cpp_ref_count() == 1)
assert(b:__cpp_ref_count() == 2)
assert(c:__cpp_ownerref_count() == 2)
count_obj(3)

d = b:ip()
assert(c:__cpp_ref_count() == 1)
assert(d:__cpp_ref_count() == 1)
assert(b:__cpp_ref_count() == 3)
assert(c:__cpp_ownerref_count() == 3)
count_obj(4)

d = nil
gc()
assert(c:__cpp_ref_count() == 1)
assert(b:__cpp_ref_count() == 2)
assert(c:__cpp_ownerref_count() == 2)
count_obj(3)

b = nil
gc()
assert(c:__cpp_ref_count() == 1)
assert(c:__cpp_ownerref_count() == 1)
-- As its ref count is not 0, the underlying object under b should still exists
-- due to c
count_obj(3)

c = nil
gc()
-- C held the last reference to s, so it disappears with him
count_obj(1)

a = nil
gc()
count_obj(0)
