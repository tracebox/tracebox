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
	l_ip_ref (Crafter::IP *i, lua_State *l) : l_layer_ref<Crafter::IP>(i, l) {}
	l_ip_ref(l_ip_ref *r, lua_State *l) : l_layer_ref<Crafter::IP>(r, l) {}
	template<class T>
	l_ip_ref(l_ref<T> *r, Crafter::IP *i, lua_State *l) : l_layer_ref<Crafter::IP>(r, i, l) {}
	~l_ip_ref() {}

	static int l_IP(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
