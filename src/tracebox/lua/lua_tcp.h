/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors. 
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_TCP_H_
#define __LUA_TCP_H_

#include "lua_crafter.hpp"

struct l_tcp_ref : public l_layer_ref<Crafter::TCP> {
	l_tcp_ref (Crafter::TCP *i, lua_State *l) : l_layer_ref<Crafter::TCP>(i, l) {}
	l_tcp_ref(l_tcp_ref *r) : l_layer_ref<Crafter::TCP>(r) {}
	template<class T>
	l_tcp_ref(l_ref<T> *r, Crafter::TCP *i) : l_layer_ref<Crafter::TCP>(r, i) {}
	~l_tcp_ref() {}

	static int l_TCP(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
