/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_PACKET_HPP_
#define __LUA_PACKET_HPP_

#include "lua_crafter.hpp"

struct l_packet_ref : public l_crafter_ref<Crafter::Packet> {
	l_packet_ref(Crafter::Packet *i, lua_State *l)
		: l_crafter_ref<Crafter::Packet>(i, l) {}
	l_packet_ref(l_packet_ref *r, lua_State *l)
		: l_crafter_ref<Crafter::Packet>(r, l) {}
	template<class T>
	l_packet_ref(l_ref<T> *r, Crafter::Packet *i, lua_State *l)
		: l_crafter_ref<Crafter::Packet>(r, i, l) {}
	~l_packet_ref() {}

	template<class C>
	static int get_layer(lua_State *l)
	{
		l_ref<Crafter::Packet> *ref = l_ref<Crafter::Packet>::get_instance(l, 1);
		new l_layer_ref<C>(ref, ref->val->GetLayer<C>(), l);
		return 1;
	};

	static int source(lua_State *l);
	static int destination(lua_State *l);
	static int send(lua_State *l);
	static int send_receive(lua_State *l);
	static void register_members(lua_State *l);
};

#endif
