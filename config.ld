file = {
    'src/tracebox/lua/lua_init.cpp',
	'src/tracebox'
}
merge = true
title = 'Lua bindings for Tracebox'
boilerplate = true
project = 'Tracebox'
format = 'markdown'
description = [[
# Tracebox, a middlebox detection tool
## Basic use of the Lua API
When run, the scripts have preset global variables and functoin, listed in @{Globals}.
The most basic script is made of 3 parts:

1. Probe packet definition, using successive concatenation of packet layers, see @{Globals}.

        pkt = ip{dst='185.31.18.133'} / tcp{dst=80} / raw('GET /index.html HTTP/1.1\r\n')

2. Callback function definition, which will be called after each probe packet has been echoed back by intermediate routers on the path, see @{Globals:tracebox_callback}.

        function cb(ttl, r_ip, probe, rcv, mod)
		    print('At hop ' .. ttl)
		    print('Received: ' .. tostring(rcv))
	    end

3. tracebox() function call, see @{Globals:tracebox}, with the created probe packet and callback function, which will run tracebox and call the callback with the detected packet modifications and return the final received packet received from the target, if any.

        result = tracebox(pkt, {callback='cb'})
	    print(tostring(result))

## Extending the LUA API
TBD
]]
