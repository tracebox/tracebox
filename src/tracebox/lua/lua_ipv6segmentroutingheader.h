/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_IPV6SEGMENTROUTINGHEADER_H_
#define __LUA_IPV6SEGMENTROUTINGHEADER_H_

#include "lua_layer.hpp"

struct l_ipv6segmentroutingheader_ref : public l_layer_ref<Crafter::IPv6SegmentRoutingHeader> {
	using l_layer_ref<Crafter::IPv6SegmentRoutingHeader>::l_layer_ref;

	static int l_IPv6SegmentRoutingHeader_SetSegments(lua_State *l);
	static int l_IPv6SegmentRoutingHeader_SetPolicyList(lua_State *l);
	static int l_IPv6SegmentRoutingHeader_SetHMAC(lua_State *l);
	static int l_IPv6SegmentRoutingHeader(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
