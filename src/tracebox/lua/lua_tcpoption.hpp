/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_TCPOPTION_H_
#define __LUA_TCPOPTION_H_

#include "lua_layer.hpp"

struct l_tcpoption_ref : public l_layer_ref<Crafter::TCPOptionLayer> {
	using l_layer_ref<Crafter::TCPOptionLayer>::l_layer_ref;

	template<class C>
	static C* new_option_ref(lua_State *l)
	{
		C *o = new C();
		new l_tcpoption_ref(o, l);
		return o;
	};
	static int l_TCPOption(lua_State *l);
	static int l_TCP_NOP(lua_State *l);
	static int l_TCP_EOL(lua_State *l);
	static int l_TCP_SACKP(lua_State *l);
	static int l_TCP_SACK(lua_State *l);
	static int l_TCP_MSS(lua_State *l);
	static int l_TCP_WindowScale(lua_State *l);
	static int l_TCP_MPTCPJoin(lua_State *l);
	static int l_TCP_MPTCPCapable(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
