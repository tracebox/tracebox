/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_base.hpp"
#include "lua_arg.h"

#include "crafter/Utils/IPResolver.h"

#include <ctime>

/***
 * @module Globals
 */

static void print_object(lua_State *L, int i, std::ostream& out)
{
	int t = lua_type(L, i);
	out << lua_typename(L, t) << ": ";
	switch (t) {
		case LUA_TSTRING:  /* strings */
			out << lua_tostring(L, i);
			break;

		case LUA_TBOOLEAN:  /* booleans */
			out << (lua_toboolean(L, i) ? "true" : "false");
			break;

		case LUA_TNUMBER:  /* numbers */
			out << lua_tonumber(L, i);
			break;

		case LUA_TUSERDATA:
			dynamic_cast<_ref_base*>((*(_ref_base**)
						(lua_touserdata(L, i))))->debug(out);
			break;

		default:  /* other values */
			break;
	}
}

void stackDump (lua_State *L, const char* f, size_t l, std::ostream& out) {
	out << "Globals:" << std::endl;
	lua_pushglobaltable(L);
	lua_pushnil(L);
	while (lua_next(L,-2) != 0) {
		if (lua_isstring(L, -2))
			out << "[" << luaL_checkstring(L, -2) << "] ";
		print_object(L, -1, out);
		lua_pop(L, 1);
		out << " / ";
	}
	lua_pop(L,1);
	out << "------------" << std::endl;

	int i;
	int top = lua_gettop(L);
	out << "Stack content (at " << f << "/" << l << "):" << std::endl;
	for (i = 1; i <= top; i++) {
		out << "[" << i << "] ";
		print_object(L, i, out);
		out << std::endl;
	}
	lua_pop(L, i);
	out << "===========" << std::endl;
}

/***
 * Suspend the current execution thread for a fixed amount of time
 * @function sleep
 * @tparam num the number of milliseconds during which the thread should sleep
 */
int l_sleep(lua_State *l)
{
	long ms = luaL_checkinteger(l, 1);
	struct timespec tp;
	tp.tv_nsec = 1000 * (ms % 1000);
	tp.tv_sec = ms / 1000;

	if (nanosleep(&tp, NULL))
		std::perror("sleep() failed");

	return 0;
}

static int l_dn(lua_State *l, int ai_family)
{
	const char *hostname = luaL_checkstring(l, 1);
	std::string r;
	int err = Crafter::GetAddress(std::string(hostname), r, ai_family);
	if (err) {
		std::cerr << "Could not resolve " << hostname
			<< " : " << gai_strerror(err) << std::endl;
		lua_pushnil(l);
	} else {
		lua_pushstring(l, r.c_str());
	}
	return 1;
}

/***
 * Resolve a domain name to an IPv6 address
 * @function dn6
 * @tparam string a domain name. If it is an IP address, does nothing
 * @treturn string the corresponding IPv6 address, or nil if the call failed
 */
int l_dn6(lua_State *l)
{
	return l_dn(l, AF_INET6);
}

/***
 * Resolve a domain name to an IPv4 address
 * @function dn4
 * @tparam string a domain name. If it is an IP address, does nothing
 * @treturn string the corresponding IPv4 address, or nil if the call failed
 */
int l_dn4(lua_State *l)
{
	return l_dn(l, AF_INET);
}

/***
 * Attempt to map the given IP address to a domain name
 * @function gethostname
 * @tparam string an IP address, does nothing on domain names
 * @treturn string the corresponding IP address, either v4 or v6
 */
int l_gethostname(lua_State *l)
{
	const char *ip = luaL_checkstring(l, 1);
	lua_pushstring(l, Crafter::GetHostname(std::string(ip)).c_str());
	return 1;
}

/***
 * Set of functions to help debugging the bindings
 * @section Debugging
 */
/***
 * Return a string containing the content of the lua C stack
 * @function __dump_c_stack
 * @treturn string the content of the C stack
 * @within Debugging
 */
int l_dump_stack(lua_State *l)
{
	std::ostringstream s;
	lua_Debug ar;
	lua_getstack(l, 1, &ar);
	lua_getinfo(l, "l", &ar);
	stackDump(l, "Called from Lua", ar.currentline, s);
	lua_pushstring(l, s.str().c_str());
	return 1;
}

/***
 * Return the number of objects that are referenced
 * @function __cpp_object_count
 * @treturn num object_count
 * @within Debugging
 */
int l_cpp_object_count(lua_State *l)
{
	lua_pushinteger(l, _ref_base::instance_count);
	return 1;
}

/***
 * Return a random number between 0 (inclusive) and the given bound (exclusive) if any
 * @function random
 * @tparam[opt] num UB
 * @treturn num n
 */
int l_random(lua_State *l)
{
	int max = UINT_MAX;
	if (lua_gettop(l) > 0)
		max = luaL_checkinteger(l, 1);
	l_data_type<int>(rand() % max).push(l);
	return 1;
}
