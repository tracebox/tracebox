#ifndef __LUA_RAW_H_
#define __LUA_RAW_H_

#include "lua_crafter.hpp"

struct l_raw_ref : public l_layer_ref<Crafter::RawLayer> {
	l_raw_ref (Crafter::RawLayer *i, lua_State *l)
		: l_layer_ref<Crafter::RawLayer>(i, l) {}
 	template<class T>
	l_raw_ref(l_ref<T> *r, Crafter::RawLayer *i)
		: l_layer_ref<Crafter::RawLayer>(r, i) {}
	~l_raw_ref() {}

	static int l_Raw(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
