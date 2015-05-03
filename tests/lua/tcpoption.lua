--
-- Tracebox -- A middlebox detection tool
--
--  Copyright 2013-2015 by its authors.
--  Some rights reserved. See LICENSE, AUTHORS.
--

function edo()
	pkt = IP / TCP / EDO / MSS / MPCAPABLE/ raw('Hello World!')
	print(pkt)
	bytes=pkt:bytes()
	print(pkt:hexdump())
	assert(bytes[33] == 112)-- (offset =7 (5 + 2)<<4, reserved =0)
	-- EDO TCP Option
	assert(bytes[44] == 6)-- (length)
	assert(bytes[48] == 11)-- (header length)
	-- TCP option after EDO
	tcpop={2,4,5,180,   -- MSS option
	30,12,0,129} --  MP Capable option
	for i = 1, 8 do
	   assert(bytes[i+48] == tcpop[i])
	end

end

edo()

