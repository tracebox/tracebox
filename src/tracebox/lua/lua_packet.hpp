/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_PACKET_HPP_
#define __LUA_PACKET_HPP_

#include "lua_crafter.hpp"
#include "lua_layer.hpp"

struct l_packet_ref : public l_crafter_ref<Crafter::Packet> {
	using l_crafter_ref<Crafter::Packet>::l_crafter_ref;

	template<class C>
	static int get_layer(lua_State *l)
	{
		std::shared_ptr<Crafter::Packet> ref =
			l_packet_ref::get_owner<Crafter::Packet>(l, 1);
		C *layer = ref->GetLayer<C>();
		if (layer)
			new l_layer_ref<C>(layer, ref, l);
		else
			lua_pushnil(l);
		return 1;
	};

	static int source(lua_State *l);
	static int destination(lua_State *l);
	static int send(lua_State *l);
	static int send_receive(lua_State *l);
	static int iplayer(lua_State *l);
	static int l_bytes(lua_State *l);
	static int l_ts(lua_State *l);
	static int l_get(lua_State *l);
	static int l_getall(lua_State *l);
	static void register_members(lua_State *l);
};

#endif
