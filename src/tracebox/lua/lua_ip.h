#ifndef __LUA_IP_H_
#define __LUA_IP_H_

#include "lua_crafter.hpp"

struct l_ip_ref : public l_layer_ref<Crafter::IP> {
	l_ip_ref (Crafter::IP *i, lua_State *l) : l_layer_ref<Crafter::IP>(i, l) {}
	template<class T>
	l_ip_ref(l_ref<T> *r, Crafter::IP *i) : l_layer_ref<Crafter::IP>(r, i) {}
	~l_ip_ref() {}

	static int l_IP(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
