/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_crafter.hpp"
#include "lua_arg.h"
#include "lua_packet.hpp"

using namespace Crafter;

/***
 * Abstract type, providing the basic methods supported by most objects,
 * inherits from @{__cpp_obj}.
 * @classmod Base_Object
 */
/***
 * Get the number of bytes in this layer
 * @function size
 * @treturn num byte_count
*/
/***
 * Return the textual representation of the object.
 * @function print
 * @see tostring
 * @treturn string
 */
/***
 * Return the Hexdacimal representation of the object.
 * @function hexdump
 * @treturn string
 */
/***
 * Concatenate two objects into a Packet
 * @function __concat
 * @usage pkt = IP / TCP / raw("Hello World!")
 * @treturn Packet
 */
/***
 * Same than @{__concat}
 * @function __add
 * @see __concat
 */
/***
 * Same than @{__concat}
 * @function __div
 * @see __concat
 */
/***
 * Same than @{print}
 * @function __tostring
 * @see print
 */

/***
 * Get this object cpp baseclass, mostly Layer or Packet. This is an opaque value.
 * @tfield string __tbx_baseclass
 */
const char* lua_tbx::base_class_field = "__tbx_baseclass";

int lua_tbx::l_concat(lua_State *l)
{
	Crafter::Layer *l1 = lua_tbx::get_udata<Crafter::Layer>(l, 1);
	Crafter::Packet *p1 = lua_tbx::get_udata<Crafter::Packet>(l, 1);
	Crafter::Layer *l2 = lua_tbx::get_udata<Crafter::Layer>(l, 2);
	Crafter::Packet *p2 = lua_tbx::get_udata<Crafter::Packet>(l, 2);

	if (l1 && l2) {
		Crafter::Packet *pkt = l_packet_ref::new_ref(l);
		pkt->PushLayer(*l1);
		pkt->PushLayer(*l2);
	} else if (p1 && l2) {
		p1->PushLayer(*l2);
		lua_pop(l, 1);
	} else if (l1 && p2) {
		Crafter::Packet *pkt = l_packet_ref::new_ref(l);
		pkt->PushLayer(*l1);
		*pkt /= *p2;
	} else if (p1 && p2){
		*p1 /= *p2;
		lua_pop(l, 1);
	} else {
		return 0;
	}
	return 1;
}
