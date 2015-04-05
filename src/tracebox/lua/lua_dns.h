/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_DNS_H_
#define __LUA_DNS_H_

#include "lua_crafter.hpp"

struct l_dns_ref : public l_layer_ref<Crafter::DNS> {
	using l_layer_ref<Crafter::DNS>::l_layer_ref;

	static int l_DNS(lua_State *l);
	static int l_add_query(lua_State *l);
	static int l_add_answer(lua_State *l);
	static int l_add_authority(lua_State *l);
	static int l_add_additional(lua_State *l);
	static int l_queries(lua_State *l);
	static int l_answers(lua_State *l);
	static int l_authority(lua_State *l);
	static int l_additional(lua_State *l);
	static void register_members(lua_State *l);

	private:
	template<class C>
	void push_vector(lua_State *l, std::vector<C> &v);
};

struct l_dnsquery_ref : public l_ref<Crafter::DNS::DNSQuery> {
	using l_ref<Crafter::DNS::DNSQuery>::l_ref;

	static int l_DNSQuery(lua_State *l);
	static int l_print(lua_State *l) { return push_streamfunc(l, &Crafter::DNS::DNSQuery::Print); }
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

struct l_dnsanswer_ref : public l_ref<Crafter::DNS::DNSAnswer> {
	using l_ref<Crafter::DNS::DNSAnswer>::l_ref;

	static int l_DNSAnswer(lua_State *l);
	static int l_print(lua_State *l) { return push_streamfunc(l, &Crafter::DNS::DNSAnswer::Print); }
	static void register_members(lua_State *l);
};

#endif
