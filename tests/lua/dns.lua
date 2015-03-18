--
-- Tracebox -- A middlebox detection tool
--
--  Copyright 2013-2015 by its authors. 
--  Some rights reserved. See LICENSE, AUTHORS.
--

assert(dn4('localhost') == '127.0.0.1')
assert(dn4('127.0.0.1') == '127.0.0.1')
assert(dn6('::1') == '::1')
assert(dn6('localhost') == '::1')
-- Can't really test resolutions over the internet due to load balancers/aliasing ...
-- But reverse should be stable!
assert(gethostname('8.8.8.8') == 'google-public-dns-a.google.com')
assert(gethostname('130.104.5.100') == 'uclouvain.be')
assert(gethostname('2001:6a8:3081:1::53') == 'ns1.sri.ucl.ac.be')
