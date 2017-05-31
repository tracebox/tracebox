/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_PARTIALTCP_H_
#define __LUA_PARTIALTCP_H_

#include "lua_layer.hpp"
#include "../PartialHeader.h"

struct l_partialtcp_ref : public l_layer_ref<Crafter::PartialTCP> {
	using l_layer_ref<Crafter::PartialTCP>::l_layer_ref;

	static void register_members(lua_State *l);
};

#endif
