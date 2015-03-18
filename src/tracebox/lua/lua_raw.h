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
	l_raw_ref (Crafter::RawLayer *i, lua_State *l)
		: l_layer_ref<Crafter::RawLayer>(i, l) {}
 	l_raw_ref(l_raw_ref *r) : l_layer_ref<Crafter::RawLayer>(r) {}
	template<class T>
	l_raw_ref(l_ref<T> *r, Crafter::RawLayer *i)
		: l_layer_ref<Crafter::RawLayer>(r, i) {}
	~l_raw_ref() {}

	static int l_Raw(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
