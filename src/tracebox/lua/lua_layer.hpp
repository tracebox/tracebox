
/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_LAYER_HPP_
#define __LUA_LAYER_HPP_

#include "lua_crafter.hpp"

template<class C>
struct l_layer_ref : public l_crafter_ref<C> {
	using l_crafter_ref<C>::l_crafter_ref;

	static void register_members(lua_State *l)
	{
		l_crafter_ref<C>::template register_members<Crafter::Layer>(l);
	}

	protected:
	virtual ~l_layer_ref() {}
};


#endif
