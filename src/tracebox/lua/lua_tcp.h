/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_TCP_H_
#define __LUA_TCP_H_

#include "lua_layer.hpp"

struct l_tcp_ref : public l_layer_ref<Crafter::TCP> {
	using l_layer_ref<Crafter::TCP>::l_layer_ref;

	static int l_TCP(lua_State *l);
	static int l_hasflags(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
