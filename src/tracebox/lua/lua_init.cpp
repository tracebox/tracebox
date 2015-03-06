#include "lua_global.h"


using namespace Crafter;

template<class C>
static int constructor(lua_State *l)
{
	l_crafter_ref<C> *r = new l_crafter_ref<C>(new C(), l);
	return r != NULL;
};

#define _INIT_TYPE_META(ref_t, t, l) \
	do { \
	const char *n = TNAME(t); \
	luaL_newmetatable(l, n); \
	ref_t::register_members(l); \

#define _INIT_TYPE_GLOBALS(ref_t, t, l) \
	lua_pushvalue(l, -1); \
	lua_setfield(l, -1, "__index"); \
	lua_setglobal(l,  n); \
	ref_t::register_globals(l); } \
	while(0)


/* Populate the tname<x> template */
L_EXPOSE_TYPE(Layer);
L_EXPOSE_TYPE(Packet);
L_EXPOSE_TYPE(IP);
L_EXPOSE_TYPE(IPOptionLayer);
L_EXPOSE_TYPE(IPv6);
L_EXPOSE_TYPE(IPv6SegmentRoutingHeader);
L_EXPOSE_TYPE(TCP);
L_EXPOSE_TYPE(TCPOptionLayer);
L_EXPOSE_TYPE(UDP);
L_EXPOSE_TYPE(ICMP);
L_EXPOSE_TYPE(RawLayer);
L_EXPOSE_TYPE(PacketModifications);
L_EXPOSE_TYPE(FWFilter);

/*
 * 1. Create & fill associated metatable
 * 2. Squeeze in a new() constructor
 * 3. Register globals functions/values for that type
 */
#define INIT_TYPE(ref_t, t, l) \
	_INIT_TYPE_META(ref_t, t, l) \
	meta_bind_func(l, "new", constructor<t>);\
	_INIT_TYPE_GLOBALS(ref_t, t, l)

/*
 * 1. Create & fill associated metatable
 * 2. Register globals functions/values for that type
 * ! no new() constructor !
 */
#define INIT_NONW(ref_t, t, l) \
	_INIT_TYPE_META(ref_t, t, l) \
	_INIT_TYPE_GLOBALS(ref_t, t, l)

lua_State *l_init()
{
	lua_State * l = luaL_newstate();
	luaL_openlibs(l);

	/* disable libcrafter warnings */
	Crafter::ShowWarnings = 0;

	/* Create metatables for every types and
	 * add global entries (functions/objects) */
	INIT_TYPE(l_packet_ref,                    Packet,                   l);
	INIT_TYPE(l_ip_ref,                        IP,                       l);
	INIT_NONW(l_ipoption_ref,                  IPOptionLayer,            l);
	INIT_TYPE(l_ipv6_ref,                      IPv6,                     l);
	INIT_TYPE(l_ipv6segmentroutingheader_ref,  IPv6SegmentRoutingHeader, l);
	INIT_TYPE(l_tcp_ref,                       TCP,                      l);
	INIT_NONW(l_tcpoption_ref,                 TCPOptionLayer,           l);
	INIT_TYPE(l_udp_ref,                       UDP,                      l);
	INIT_TYPE(l_icmp_ref,                      ICMP,                     l);
	INIT_TYPE(l_raw_ref,                       RawLayer,                 l);
	INIT_NONW(l_packetmodifications_ref,       PacketModifications,      l);
	INIT_NONW(l_fwfilter_ref,                  FWFilter,                 l);

	/* Register the tracebox function */
	lua_register(l, "tracebox", l_Tracebox);

	return l;
}
