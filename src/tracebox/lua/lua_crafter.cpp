#include "lua_crafter.hpp"
#include <cstring>

using namespace Crafter;

/* --- lua_tbx */

const char* lua_tbx::base_class_field = "__tbx_baseclass";

template<class Base>
static Base* get_udata(lua_State *l, int n)
{
	luaL_checktype(l, n, LUA_TUSERDATA);
	/* We want a custom data type */
	if (!luaL_getmetafield(l, n, lua_tbx::base_class_field))
		return NULL;
	/* We want the object the have the specified base class name */
	const char *basename = l_data_type<const char*>::get(l, -1);
	lua_pop(l, 1);
	if (strcmp(TNAME(Base), basename))
		return NULL;
	return (*static_cast<l_ref<Base>**>(lua_touserdata(l, n)))->val;
};

int lua_tbx::l_concat(lua_State *l)
{
	Crafter::Layer *l1 = get_udata<Crafter::Layer>(l, 1);
	Crafter::Packet *p1 = get_udata<Crafter::Packet>(l, 1);
	Crafter::Layer *l2 = get_udata<Crafter::Layer>(l, 2);
	Crafter::Packet *p2 = get_udata<Crafter::Packet>(l, 2);

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

void l_packet_ref::register_members(lua_State *l)
{
	l_crafter_ref<Packet>::register_members<Packet>(l);
	meta_bind_func(l, "new", new_packet);
	meta_bind_func(l, "source", source);
	meta_bind_func(l, "destination", destination);
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
