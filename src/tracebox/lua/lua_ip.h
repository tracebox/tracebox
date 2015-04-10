/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_IP_H_
#define __LUA_IP_H_

#include "lua_crafter.hpp"

struct l_ip_ref : public l_layer_ref<Crafter::IP> {
	using l_layer_ref<Crafter::IP>::l_layer_ref;

	static int l_IP(lua_State *l);
	static int l_payloadlen(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
