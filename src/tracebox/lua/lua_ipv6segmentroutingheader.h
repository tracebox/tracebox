#ifndef __LUA_IPV6SEGMENTROUTINGHEADER_H_
#define __LUA_IPV6SEGMENTROUTINGHEADER_H_

#include "lua_crafter.hpp"

struct l_ipv6segmentroutingheader_ref : public l_layer_ref<Crafter::IPv6SegmentRoutingHeader> {
	l_ipv6segmentroutingheader_ref (Crafter::IPv6SegmentRoutingHeader *i, lua_State *l)
		: l_layer_ref<Crafter::IPv6SegmentRoutingHeader>(i, l) {}
	template<class T>
	l_ipv6segmentroutingheader_ref(l_ref<T> *r, Crafter::IPv6SegmentRoutingHeader *i)
		: l_layer_ref<Crafter::IPv6SegmentRoutingHeader>(r, i) {}
	~l_ipv6segmentroutingheader_ref() {}

	static int l_IPv6SegmentRoutingHeader_SetSegments(lua_State *l);
	static int l_IPv6SegmentRoutingHeader_SetPolicyList(lua_State *l);
	static int l_IPv6SegmentRoutingHeader_SetHMAC(lua_State *l);
	static int l_IPv6SegmentRoutingHeader(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
