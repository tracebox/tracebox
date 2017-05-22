/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_IPOption_H_
#define __LUA_IPOption_H_

#include "lua_layer.hpp"

struct l_ipoption_ref : public l_layer_ref<Crafter::IPOptionLayer> {
	using l_layer_ref<Crafter::IPOptionLayer>::l_layer_ref;

	template<class C>
	static C* new_option_ref(lua_State *l)
	{
		C *o = new C();
		new l_ipoption_ref(o, l);
		return o;
	};
	static int l_IPOption(lua_State *l);
	static int l_IP_NOP(lua_State *l);
	static int l_IP_EOL(lua_State *l);
	static int l_IP_SSRR(lua_State *l);
	static int l_IP_LSRR(lua_State *l);
	static int l_IP_RR(lua_State *l);
	static int l_IP_Traceroute(lua_State *l);
	static void register_globals(lua_State *l);
	static void register_members(lua_State *l);
};

#endif
