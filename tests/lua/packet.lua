--
-- Tracebox -- A middlebox detection tool
--
--  Copyright 2013-2015 by its authors. 
--  Some rights reserved. See LICENSE, AUTHORS.
--

function ping(to)
	pkt = ip{dst = dn4(to)} / ICMPEchoReq(1, 2) / raw('Hello World!')
	reply = pkt:sendrecv{}
	assert(reply ~= nil)
	assert(reply:icmp() ~= nil)
	r = reply:payload()
	if raw then
		assert(tostring(r) == tostring(pkt:payload()))
	end
end

p = ip{dst = dn6('google.com')} / UDP
assert(p:send() == nil) -- Check that we don't pollute the stack
ping('localhost')
ping('google.com')
