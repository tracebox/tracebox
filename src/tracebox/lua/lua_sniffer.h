/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_SNIFFER_H_
#define __LUA_SNIFFER_H_

#include "lua_base.hpp"
#include "../sniffer.h"

struct l_sniffer_ref : public l_ref<TbxSniffer> {
	using l_ref<TbxSniffer>::l_ref;

	static int l_Sniffer(lua_State *l);
	static int l_start(lua_State *l);
	static int l_stop(lua_State *l);
	static int l_recv(lua_State *l);

	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);

	lua_State *ctx;
	int cb;
};

#endif
