/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_FWFilter_H_
#define __LUA_FWFilter_H_

#include "lua_base.hpp"

class FWFilter {
	int src, dst;
#ifdef __APPLE__
	int id;
#endif
	const char *proto;
	bool closed;
public:
	FWFilter(int src, int dst, const char *proto);

	~FWFilter() { close(); }

	void close();
};

struct l_fwfilter_ref : public l_ref<FWFilter> {
	using l_ref<FWFilter>::l_ref;

	static int l_FWFilter_close(lua_State *l);
	static int l_TraceboxFilter(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
