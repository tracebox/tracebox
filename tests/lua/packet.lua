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

p = ipv6{dst = dn6('google.com')} / UDP
-- assert(p:send() == nil) -- Check that we don't pollute the stack
ping('localhost')
ping('google.com')

str = 'Hello World'
pkt = IP/TCP/raw(str)
bytes = pkt:bytes()
assert(#bytes == 20 + 20 + 11)
assert(bytes[1] == 69) -- version=4<<4, IHL=5
assert(bytes[33] == 80) -- offset =5<<4, reserved =0)
assert(bytes[51] == 100) -- last letter, d

pkt = ip{dst='1.2.3.4'}/tcp{dst=40}
assert(pkt:get(IP):dest() == '1.2.3.4')
assert(pkt:get(TCP):getdest() == 40)
assert(pkt:get(MPCAPABLE) == nil)
