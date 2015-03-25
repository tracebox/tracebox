/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_SNIFFER_H_
#define __LUA_SNIFFER_H_

#include "lua_base.hpp"
#include "../sniffer.h"

struct l_sniffer_ref : public l_ref<TbxSniffer> {
	l_sniffer_ref(TbxSniffer *i, lua_State *l)
		: l_ref<TbxSniffer>(i, l){}
	l_sniffer_ref(l_sniffer_ref *f, lua_State *l)
		: l_ref<TbxSniffer>(f, l){}
	template<class T>
	l_sniffer_ref(l_ref<T> *r, TbxSniffer *i, lua_State *l)
		: l_ref<TbxSniffer>(r, i, l){}
	~l_sniffer_ref() {}

	static int l_Sniffer(lua_State *l);
	static int l_start(lua_State *l);
	static int l_stop(lua_State *l);

	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);

	lua_State *ctx;
	std::string cb;
};

#endif
