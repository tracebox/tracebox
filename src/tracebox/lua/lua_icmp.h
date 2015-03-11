#ifndef __LUA_ICMP_H_
#define __LUA_ICMP_H_

#include "lua_crafter.hpp"

struct l_icmp_ref : public l_layer_ref<Crafter::ICMP> {
	l_icmp_ref (Crafter::ICMP *i, lua_State *l) : l_layer_ref<Crafter::ICMP>(i, l) {}
	template<class T>
	l_icmp_ref(l_ref<T> *r, Crafter::ICMP *i) : l_layer_ref<Crafter::ICMP>(r, i) {}
	~l_icmp_ref() {}

	static int l_ICMP(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
