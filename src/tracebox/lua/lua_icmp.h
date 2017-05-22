/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_ICMP_H_
#define __LUA_ICMP_H_

#include "lua_layer.hpp"

struct l_icmp_ref : public l_layer_ref<Crafter::ICMP> {
	using l_layer_ref<Crafter::ICMP>::l_layer_ref;

	static int l_ICMP(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
