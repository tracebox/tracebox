/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_RAW_H_
#define __LUA_RAW_H_

#include "lua_crafter.hpp"

struct l_raw_ref : public l_layer_ref<Crafter::RawLayer> {
	using l_layer_ref<Crafter::RawLayer>::l_layer_ref;

	static int l_Raw(lua_State *l);
	static int l_data(lua_State *l);
	static int l_bytes(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
