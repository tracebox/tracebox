/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_IPV6_H_
#define __LUA_IPV6_H_

#include "lua_crafter.hpp"

struct l_ipv6_ref : public l_layer_ref<Crafter::IPv6> {
	using l_layer_ref<Crafter::IPv6>::l_layer_ref;

	static int l_IPv6(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
