#include "lua_packetmodifications.h"

int l_packetmodifications_ref::l_PacketModifications_print(lua_State *l)
{
	std::ostringstream stream;
	PacketModifications *o = l_ref<PacketModifications>::get(l, 1);
	o->Print(stream);
	l_data_type<std::string>(stream.str()).push(l);
	return 1;
}

void l_packetmodifications_ref::register_members(lua_State *l)
{
	l_ref<PacketModifications>::register_members(l);
	meta_bind_func(l, "__tostring", l_PacketModifications_print);
	meta_bind_func(l, "print", l_PacketModifications_print);
}

void l_packetmodifications_ref::debug(std::ostream& out)
{
	l_ref<PacketModifications>::debug(out);
	this->val->Print(out, true);
}
