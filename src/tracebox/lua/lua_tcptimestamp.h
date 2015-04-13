/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_TCPTIMESTAMP_H_
#define __LUA_TCPTIMESTAMP_H_

#include "lua_crafter.hpp"

struct l_tcptsopt_ref : public l_layer_ref<Crafter::TCPOptionTimestamp> {
	using l_layer_ref<Crafter::TCPOptionTimestamp>::l_layer_ref;
	static int l_TCP_Timestamp(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
