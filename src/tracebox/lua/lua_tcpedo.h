/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_TCPEDO_H_
#define __LUA_TCPEDO_H_

#include "lua_crafter.hpp"

struct l_tcpedoopt_ref : public l_layer_ref<Crafter::TCPEDO> {
	using l_layer_ref<Crafter::TCPEDO>::l_layer_ref;
	static int l_TCP_EDO(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

struct l_tcpedoropt_ref : public l_layer_ref<Crafter::TCPEDORequest> {
	using l_layer_ref<Crafter::TCPEDORequest>::l_layer_ref;
	static int l_TCP_EDOR(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
