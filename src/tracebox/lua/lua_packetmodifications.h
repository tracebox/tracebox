#ifndef __LUA_PACKETMODIFICATIONS_H_
#define __LUA_PACKETMODIFICATIONS_H_

#include "lua_crafter.hpp"
#include "../PacketModification.h"


struct l_packetmodifications_ref : public l_ref<PacketModifications> {
	l_packetmodifications_ref (PacketModifications *i, lua_State *l)
		: l_ref<PacketModifications>(i, l) {}
	template<class T>
	l_packetmodifications_ref(l_ref<T> *r, PacketModifications *i)
		: l_ref<PacketModifications>(r, i) {}
	~l_packetmodifications_ref() {}

	void debug(std::ostream&);

	static int l_PacketModifications_print(lua_State *l);
	static void register_members(lua_State *l);
};

#endif
