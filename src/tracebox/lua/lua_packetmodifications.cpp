/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_packetmodifications.h"
#include "lua_packet.hpp"
#include "lua_crafter.hpp"

using namespace Crafter;

/***
 * A set of modifications between packets
 * @classmod PacketModifications
 */
/***
 * Build a new PacketModifications
 * @function new
 * @tparam Packet original the reference packet to compare to
 * @tparam Packet receivd the new packet that has been modified
 * @treturn PacketModifications mod the set of modifications
 */
int l_packetmodifications_ref::l_PacketModifications(lua_State *l)
{
	Packet *original = l_packet_ref::get(l, 1);
	Packet *received = new Packet(*l_packet_ref::get(l, 2));
	PacketModifications *mod = PacketModifications::ComputeModifications(
			original, &received);
	new l_packetmodifications_ref(mod, l);
	return 1;
}

int l_packetmodifications_ref::l_PacketModifications_print(lua_State *l)
{
	std::ostringstream stream;
	PacketModifications *o = l_packetmodifications_ref::get(l, 1);
	o->Print(stream);
	l_data_type<std::string>(stream.str()).push(l);
	return 1;
}

int l_packetmodifications_ref::l_get_original(lua_State *l)
{
	l_ref<PacketModifications> *r = l_packetmodifications_ref::get_instance(l, 1);
	new l_packet_ref(r, r->val->orig, l);
	return 1;
}

int l_packetmodifications_ref::l_get_received(lua_State *l)
{
	l_ref<PacketModifications> *r = l_packetmodifications_ref::get_instance(l, 1);
	new l_packet_ref(r, r->val->modif, l);
	return 1;
}

static int l_partial(lua_State *l)
{
	PacketModifications *p = l_packetmodifications_ref::get(l, 1);
	l_data_type<int>(p->partial).push(l);
	return 1;
}

void l_packetmodifications_ref::register_members(lua_State *l)
{
	l_ref<PacketModifications>::register_members(l);
	meta_bind_func(l, "new", l_PacketModifications);
	/***
	 * Return the textual representation of the object.
	 * @function print
	 * @see tostring
	 * @treturn string
	 */
	meta_bind_func(l, "__tostring", l_PacketModifications_print);
	/***
	 * Same than @{print}
	 * @function __tostring
	 * @see print
	 */
	meta_bind_func(l, "print", l_PacketModifications_print);
	/***
	 * Get the original packet as reference when computing these modifications
	 * @function original
	 * @treturn Packet original
	 */
	meta_bind_func(l, "original", l_get_original);
	/***
	 * Get the reveived packet differing from the original packet
	 * @function received
	 * @treturn Packet received
	 */
	meta_bind_func(l, "received", l_get_received);
	/***
	 * Check if the modifications have been computed based on a partial
	 * header or not
	 * @function partial
	 * @treturn num partial 0 if not from a partial header
	 */
	meta_bind_func(l, "partial", l_partial);
}

void l_packetmodifications_ref::debug(std::ostream& out)
{
	l_ref<PacketModifications>::debug(out);
	out << (void*) this << " ";
	this->val->Print(out, true);
}
