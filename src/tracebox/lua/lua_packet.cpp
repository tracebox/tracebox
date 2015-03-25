/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_packet.hpp"
#include "lua_arg.h"
#include "../tracebox.h"

using namespace Crafter;

/***
 * An object representing a Packet, inherits from @{Base_Object}
 * @classmod Packet
 */

/***
 * Get the Source IP address of this packet
 * @function source
 * @treturn string IP address
 */
int l_packet_ref::source(lua_State *l)
{
	Packet *pkt = l_packet_ref::get(l, 1);
	if (!pkt)
		lua_pushnil(l);
	else
		l_data_type<std::string>(pkt->GetLayer<IPLayer>()->GetSourceIP()).push(l);
	return 1;
}

/***
 * Get the Destination IP address of this packet
 * @function destination
 * @treturn string IP address
 */
int l_packet_ref::destination(lua_State *l)
{
	Packet *pkt = l_packet_ref::get(l, 1);
	if (!pkt)
		lua_pushnil(l);
	else
		l_data_type<std::string>(pkt->GetLayer<IPLayer>()->GetDestinationIP()).push(l);
	return 1;
}

/***
 * Create a new Packet
 * @function new
 * @treturn Packet a new empty Packet
 */
static int new_packet(lua_State *l)
{
	Packet *p = l_packet_ref::new_ref(l);
	return p != NULL;
}

/***
 * Send a packet and wait for a reply
 * @function sendrecv
 * @tparam[opt] table args A table containing the optional arguments, see @{sendrecv_args}
 */
/***
 * sendrecv arguments
 * @table sendrecv_args
 * @tfield num timeout How long to wait for a response
 * @tfield num retry How many times should we send another packet and try again
 * 	in case of timeout
 * @tfield string interface force the outgoing interface, instead of using the
 * 	default interface for the destination address
 */
int l_packet_ref::send_receive(lua_State *l)
{
	double timeout = 1;
	int retry = 3;
	const char *iface = "";
	v_arg_double_opt(l, 2, "timeout", &timeout);
	v_arg_integer_opt(l, 2, "retry", &retry);
	v_arg_string_opt(l, 2, "interface", &iface);

	std::string err, intf(iface);
	Packet *p = l_packet_ref::get(l, 1);
	if (!probe_sanity_check(p, err, intf))
		luaL_error(l, err.c_str());

	Packet *rcv = p->SendRecv(intf, timeout, retry);
	if (!rcv)
		lua_pushnil(l);
	else
		new l_packet_ref(rcv, l);
	return 1;
}

/***
 * Send a packet over the wire
 * @function send
 * @tparam[opt] string interface force the outgoing interface, instead of using the
 * 	default interface for the destination address
 */
int l_packet_ref::send(lua_State *l)
{
	Packet *p = l_packet_ref::get(l, 1);
	std::string iface, err;
	if (lua_gettop(l) > 1)
		iface = luaL_checkstring(l, 2);

	if (!probe_sanity_check(p, err, iface))
		luaL_error(l, err.c_str());

	p->Send(iface);
	return 0;
}

void l_packet_ref::register_members(lua_State *l)
{
	l_crafter_ref<Packet>::register_members<Packet>(l);
	meta_bind_func(l, "new", new_packet);
	meta_bind_func(l, "source", source);
	meta_bind_func(l, "destination", destination);
	meta_bind_func(l, "send", send);
	meta_bind_func(l, "sendrecv", send_receive);
	/* Bind all available layers */
	/***
	 * Get the IP Layer of this packet
	 * @function ip
	 * @treturn IP the IP layer or nil
	 */
	meta_bind_func(l, "ip", get_layer<IP>);
	/***
	 * Get the IPv6 Layer of this packet
	 * @function ipv6
	 * @treturn IPv6 the IPv6 layer or nil
	 */
	meta_bind_func(l, "ipv6", get_layer<IPv6>);
	/***
	 * Get the IPv6SegmentRoutingHeader Layer of this packet
	 * @function srh
	 * @treturn IPv6SegmentRoutingHeader the IPv6SegmentRoutingHeader layer or nil
	 */
	meta_bind_func(l, "srh", get_layer<IPv6SegmentRoutingHeader>);
	/***
	 * Get the TCP Layer of this packet
	 * @function tcp
	 * @treturn TCP the TCP layer or nil
	 */
	meta_bind_func(l, "tcp", get_layer<TCP>);
	/***
	 * Get the UDP Layer of this packet
	 * @function udp
	 * @treturn UDP the UDP layer or nil
	 */
	meta_bind_func(l, "udp", get_layer<UDP>);
	/***
	 * Get the ICMP Layer of this packet
	 * @function icmp
	 * @treturn ICMP the ICMP layer or nil
	 */
	meta_bind_func(l, "icmp", get_layer<ICMP>);
	/***
	 * Get the Raw Layer of this packet
	 * (a.k.a. all the data after the last known layer)
	 * @function payload
	 * @treturn Raw the Raw layer or nil
	 */
	meta_bind_func(l, "payload", get_layer<RawLayer>);
}
