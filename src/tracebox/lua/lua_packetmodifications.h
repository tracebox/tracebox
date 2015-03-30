/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_PACKETMODIFICATIONS_H_
#define __LUA_PACKETMODIFICATIONS_H_

#include "lua_crafter.hpp"
#include "../PacketModification.h"


struct l_packetmodifications_ref : public l_ref<PacketModifications> {
	using l_ref<PacketModifications>::l_ref;

	void debug(std::ostream&);

	static int l_PacketModifications_print(lua_State *l);
	static int l_PacketModifications(lua_State *l);
	static int l_get_original(lua_State *l);
	static int l_get_received(lua_State *l);
	static void register_members(lua_State *l);
};

#endif
