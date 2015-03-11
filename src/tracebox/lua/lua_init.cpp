#include "lua_global.h"

using namespace Crafter;


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
 * 2 Register globals functions/values for that type
 */
#define INIT_TYPE(ref_t, t, l) \
	do { \
	const char *n = TNAME(t); \
	luaL_newmetatable(l, n); \
	ref_t::register_members(l); \
	lua_pushvalue(l, -1); \
	lua_setfield(l, -1, "__index"); \
	lua_setglobal(l,  n); \
	ref_t::register_globals(l); } \
	while(0)

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
	INIT_TYPE(l_ipoption_ref,                  IPOptionLayer,            l);
	INIT_TYPE(l_ipv6_ref,                      IPv6,                     l);
	INIT_TYPE(l_ipv6segmentroutingheader_ref,  IPv6SegmentRoutingHeader, l);
	INIT_TYPE(l_tcp_ref,                       TCP,                      l);
	INIT_TYPE(l_tcpoption_ref,                 TCPOptionLayer,           l);
	INIT_TYPE(l_udp_ref,                       UDP,                      l);
	INIT_TYPE(l_icmp_ref,                      ICMP,                     l);
	INIT_TYPE(l_raw_ref,                       RawLayer,                 l);
	INIT_TYPE(l_packetmodifications_ref,       PacketModifications,      l);
	INIT_TYPE(l_fwfilter_ref,                  FWFilter,                 l);

	/* Register the tracebox function */
	lua_register(l, "tracebox", l_Tracebox);

	/* Register the utility functions */
	lua_register(l, "sleep", l_sleep);

	return l;
}

/***
 * Global functions and objects provided by TraceBox
 * @module Globals
 */

/***
 * Create a firewall rule to open ports on the host machine.
 * @function filter
 * @tparam Packet pkt a packet with a TCP or an UDP layer available.
 * @treturn FWFilter the firewall object that will open the source
 * 	and destination ports found in the TCP/UDP layer of the packet
 * @usage filter(IP / UDP{src=53}) -- Will open port 53 on the host machine
 */
void l_fwfilter_ref::register_globals(lua_State *l)
{
	l_ref<FWFilter>::register_globals(l);
	lua_register(l, "filter", l_TraceboxFilter);
}

/***
 * @section Layers
 */
/***
 * Shorthand for @{Raw:new}
 * @function raw
 * @tparam[opt] table args arguments
 * @see Raw:new
 * @treturn Raw a new Raw Layer object
 * @within Layers
 */
void l_raw_ref::register_globals(lua_State *l)
{
	l_layer_ref<RawLayer>::register_globals(l);
	lua_register(l, "raw", l_Raw);
}


/***
 * @section ICMP
 */
void l_icmp_ref::register_globals(lua_State *l)
{
	l_layer_ref<ICMP>::register_globals(l);
	/***
	 * Shorthand for @{ICMP:new}
	 * @function icmp
	 * @tparam[opt] table args arguments
	 * @see ICMP:new
	 * @treturn ICMP a new ICMP Layer object
	 * @within Layers
	 */
	lua_register(l, "icmp", l_ICMP);
	/***
	 * Create an ICMP Echo Request Layer
	 * @function ICMPEchoReq
	 * @tparam num id the ICMP Identification number
	 * @tparam num seq the ICMP sequenc number
	 * @treturn ICMP a new ICMP Layer object
	 * @within ICMP
	 */
	l_do(l, "function ICMPEchoReq(id,seq) return icmp{type=8,id=id,seqno=seq} end");
	/***
	 * Create an ICMP Echo Reply Layer
	 * @function ICMPEchoRep
	 * @tparam num id the ICMP Identification number
	 * @tparam num seq the ICMP sequenc number
	 * @treturn ICMP a new ICMP Layer object
	 * @within ICMP
	 */
	l_do(l, "function ICMPEchoRep(id,seq) return icmp{type=0,id=id,seqno=seq} end");
	/***
	 * Create an ICMP Destination Unreachable Layer
	 * @function ICMPDstUnreach
	 * @tparam num mtu the mtu to specify
	 * @treturn ICMP a new ICMP Layer object
	 * @within ICMP
	 */
	l_do(l, "function ICMPDstUnreach(mtu) return icmp{type=3,mtu=mtu} end");
	/***
	 * Create an ICMP Source Quench Unreachable Layer
	 * @table ICMPSrcQuench
	 * @see ICMP
	 * @within ICMP
	 */
	l_do(l, "ICMPSrcQuench=icmp{type=4}");
	/***
	 * Create an ICMP Redirect Layer
	 * @function ICMPRedirect
	 * @tparam string addr the address for the redirection
	 * @treturn ICMP a new ICMP Layer object
	 * @within ICMP
	 */
	l_do(l, "function ICMPRedirect(addr) return icmp{type=5,gw=addr} end");
	/***
	 * Create an ICMP Time Exceeded Layer
	 * @table ICMPTimeExceeded
	 * @see ICMP
	 * @within ICMP
	 */
	l_do(l, "ICMPTimeExceeded=icmp{type=11}");
}

/***
 * @section IP
 */
void l_ip_ref::register_globals(lua_State *l)
{
	l_layer_ref<IP>::register_globals(l);
	/***
	 * Shorthand for @{IP:new}
	 * @function ip
	 * @tparam[opt] table args arguments
	 * @see IP:new
	 * @treturn IP a new IP Layer object
	 * @within Layers
	 */
	lua_register(l, "ip", l_IP);
	/***
	 * A default IP layer instance
	 * @table IP
	 * @see IP:new
	 * @within IP
	 */
	l_do(l, "IP=ip({})");
}

void l_ipoption_ref::register_globals(lua_State *l)
{
	l_layer_ref<IPOption>::register_globals(l);
	/***
	 * Construct an IPOption NOP (padding, option=1), shorthand for @{IPOption:new_nop}
	 * @function ip_nop
	 * @treturn IPOption
	 * @see IPOption:new_nop
	 * @within IP
	 */
	lua_register(l, "ip_nop", l_IP_NOP);
	/***
	 * Construct an IPOption EOL (padding, option=0), shorthand for @{IPOption:new_eol}
	 * @function ip_eol
	 * @treturn IPOption
	 * @see IPOption:new_eol
	 * @within IP
	 */
	lua_register(l, "ip_eol", l_IP_EOL);
	/***
	 * Construct an IPOption RR, shorthand for @{IPOption:new_rr}
	 * @function rr
	 * @tparam num the number of IPs
	 * @treturn IPOption
	 * @see IPOption:new_rr
	 * @within IP
	 */
	lua_register(l, "rr", l_IP_RR);
	/***
	 * Construct an IPOption SSRR, shorthand for @{IPOption:new_ssrr}
	 * @function ssrr
	 * @tparam table addrs list of IPs
	 * @treturn IPOption
	 * @see IPOption:new_ssrr
	 * @within IP
	 */
	lua_register(l, "ssrr", l_IP_SSRR);
	/***
	 * Construct an IPOption LSRR, shorthand for @{IPOption:new_lsrr}
	 * @function lsrr
	 * @tparam table addrs list of IPs
	 * @treturn IPOption
	 * @see IPOption:new_lsrr
	 * @within IP
	 */
	lua_register(l, "lsrr", l_IP_LSRR);
	/***
	 * Construct an IPOption Traceroute, shorthand for @{IPOption:new_traceroute}
	 * @function traceroute
	 * @tparam string src Original IP
	 * @treturn IPOption
	 * @see IPOption:new_traceroute
	 * @within IP
	 */
	lua_register(l, "traceroute", l_IP_Traceroute);
	/***
	 * A default IP NOP object
	 * @table NOP
	 * @see IPOption
	 * @within IP
	 */
	l_do(l, "IP_NOP=ip_nop()");
	/***
	 * A default IP EOL object
	 * @table EOL
	 * @see IPOption
	 * @within IP
	 */
	l_do(l, "IP_EOL=ip_eol()");
	/***
	 * Construct a RR IPOption, with proper padding
	 * @function RR
	 * @tparam num the number of IPs
	 * @treturn IPOption
	 * @see IPOption:new_rr
	 * @within IP
	 */
	l_do(l, "function RR(n) return rr(n)/IP_NOP end");
	/***
	 * Construct a SSRR IPOption, with proper padding
	 * @function SSRR
	 * @tparam table addrs list of IPs
	 * @treturn IPOption
	 * @see IPOption:new_ssrr
	 * @within IP
	 */
	l_do(l, "function SSRR(addrs) return ssrr(addrs)/IP_NOP end");
	/***
	 * Construct a LSRR IPOption, with proper padding
	 * @function LSRR
	 * @tparam table addrs list of IPS
	 * @treturn IPOption
	 * @see IPOption:new_lsrr
	 * @within IP
	 */
	l_do(l, "function LSRR(addrs) return lsrr(addrs)/IP_NOP end");
}

/***
 * @section IPv6
 */
void l_ipv6_ref::register_globals(lua_State *l)
{
	l_layer_ref<IPv6>::register_globals(l);
	/***
	 * Shorthand for @{IPv6:new}
	 * @function ipv6
	 * @tparam[opt] table args arguments
	 * @see IPv6:new
	 * @treturn IPv6 a new IP Layer object
	 * @within Layers
	 */
	lua_register(l, "ipv6", l_IPv6);
	/***
	 * A default IPv6 layer instance
	 * @table IPv6
	 * @see IPv6
	 * @within IPv6
	 */
	l_do(l, "IPv6=ipv6({})");
}

void l_ipv6segmentroutingheader_ref::register_globals(lua_State *l)
{
	l_layer_ref<IPv6SegmentRoutingHeader>::register_globals(l);
	/***
	 * Shorthand for @{IPv6SegmentRoutingHeader:new}
	 * @function srh
	 * @tparam[opt] table args arguments
	 * @see IPv6SegmentRoutingHeader:new
	 * @treturn IPv6SegmentRoutingHeader a new IPv6SegmentRoutingHeader Layer object
	 * @within Layers
	 */
	lua_register(l, "srh", l_IPv6SegmentRoutingHeader);
	/***
	 * Create a Segment Routing Header from a list of segment
	 * @function SRH
	 * @tparam table segs a list of segments
	 * @treturn IPv6SegmentRoutingHeader
	 * @within IPv6
	 * @see IPv6SegmentRoutingHeader
	 */
	l_do(l, "function SRH(segs) return srh{segments=segs} end");
}

/***
 * @section TCP
 */
void l_tcp_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCP>::register_globals(l);
	/***
	 * Shorthand for @{TCP:new}
	 * @function tcp
	 * @tparam[opt] table args arguments
	 * @see TCP:new
	 * @treturn TCP a new TCP Layer object
	 * @within Layers
	 */
	lua_register(l, "tcp", l_TCP);
	/***
	 * A default TCP layer whose destination port is 80
	 * @table TCP
	 * @see TCP
	 * @within TCP
	 */
	l_do(l, "TCP=tcp({dst=80})");
}

void l_tcpoption_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCPOptionLayer>::register_globals(l);
	/***
	 * Construct a  TCPOption NOP (padding, kind=1), shorthand for @{TCPOption:new_nop}
	 * @function nop
	 * @treturn TCPOption
	 * @see TCPOption:new_nop
	 * @within TCP
	 */
	lua_register(l, "nop", l_TCP_NOP);
	/***
	 * Construct a  TCPOption EOL (padding, kind=0), shorthand for @{TCPOption:new_eol}
	 * @function eol
	 * @treturn TCPOption
	 * @see TCPOption:new_eol
	 * @within TCP
	 */
	lua_register(l, "eol", l_TCP_EOL);
	/***
	 * Construct a  TCPOption SACKP, shorthand for @{TCPOption:new_sackp}
	 * @function sackp
	 * @treturn TCPOption
	 * @see TCPOption:new_sackp
	 * @within TCP
	 */
	lua_register(l, "sackp", l_TCP_SACKP);
	/***
	 * Construct a  TCPOption SACK, shorthand for @{TCPOption:new_sack}
	 * @function sack
	 * @tparam table list of pairs of number, will attempt to group them 2-by-2 or flatten sublists
	 * @treturn TCPOption
	 * @see TCPOption:new_sack
	 * @within TCP
	 */
	lua_register(l, "sack", l_TCP_SACK);
	/***
	 * Construct a  TCPOption MSS, shorthand for @{TCPOption:new_mss}
	 * @function mss
	 * @tparam num the mss size
	 * @treturn TCPOption
	 * @see TCPOption:new_mss
	 * @within TCP
	 */
	lua_register(l, "mss", l_TCP_MSS);
	/***
	 * Construct a  TCPOption Timestamp, shorthand for @{TCPOption:new_timestamp}
	 * @function timestamp
	 * @tparam[opt] table arg
	 * @treturn TCPOption
	 * @see TCPOption:new_timestamp
	 * @within TCP
	 */
	lua_register(l, "timestamp", l_TCP_Timestamp);
	/***
	 * Construct a  TCPOption WScale, shorthand for @{TCPOption:new_wscale}
	 * @function wscale
	 * @tparam num the wscale shift value
	 * @treturn TCPOption
	 * @see TCPOption:new_wscale
	 * @within TCP
	 */
	lua_register(l, "wscale", l_TCP_WindowScale);
	/***
	 * Construct a  TCPOption MPCapable, shorthand for @{TCPOption:new_mpcapable}
	 * @function mpcapable
	 * @tparam[opt] table arg
	 * @treturn TCPOption
	 * @see TCPOption:new_mpcapable
	 * @within TCP
	 */
	lua_register(l, "mpcapable", l_TCP_MPTCPCapable);
	/***
	 * Construct a  TCPOption MPJoin, shorthand for @{TCPOption:new_mpjoin}
	 * @function mpjoin
	 * @tparam[opt] table arg
	 * @treturn TCPOption
	 * @see TCPOption:new_mpjoin
	 * @within TCP
	 */
	lua_register(l, "mpjoin", l_TCP_MPTCPJoin);
	/***
	 * A default TCP NOP object
	 * @table NOP
	 * @see TCPOption
	 * @within TCP
	 */
	l_do(l, "NOP=nop()");
	/***
	 * A default TCPOption EOL object
	 * @table EOL
	 * @see TCPOption:new_eol
	 * @within TCP
	 */
	l_do(l, "EOL=eol()");
	/***
	 * A default TCPOption SACKPermitted object with proper padding
	 * @table SACKP
	 * @see TCPOption:new_sackp
	 * @within TCP
	 */
	l_do(l, "SACKP=NOP/NOP/sackp()");
	/***
	 * A TCP MSS object defaulting to 1460 bytes
	 * @table MSS
	 * @see TCPOption:new_mss
	 * @within TCP
	 */
	l_do(l, "MSS=mss(1460)");
	/***
	 * A default TCP NOP object
	 * @table TS
	 * @see TCPOption:new_mss
	 * @within TCP
	 */
	l_do(l, "TS=NOP/NOP/timestamp{}");
	/***
	 * Construct a SACK Option block, with proper padding
	 * @function SACK
	 * @tparam table list of pairs
	 * @treturn TCPOption
	 * @see TCPOption:new_sack
	 * @within TCP
	 */
	l_do(l, "function SACK(blocks) return NOP/NOP/sack(blocks) end");
	/***
	 * A default TCPOption WScale object (14), with proper padding
	 * @table WSCALE
	 * @see TCPOption:new_wscale
	 * @within TCP
	 */
	l_do(l, "WSCALE=wscale(14)/NOP");
	/***
	 * A default TCPOption MPCapable object
	 * @table MPCAPABLE
	 * @see TCPOption:new_mpcapable
	 * @within TCP
	 */
	l_do(l, "MPCAPABLE=mpcapable{}");
	/***
	 * A default TCPOption MPjoin object
	 * @table MPJOIN
	 * @see TCPOption:new_mpjoin
	 * @within TCP
	 */
	l_do(l, "MPJOIN=mpjoin{}");
}

/***
 * @section UDP
 */
void l_udp_ref::register_globals(lua_State *l)
{
	l_layer_ref<UDP>::register_globals(l);
	/***
	 * Shorthand for @{UDP:new}
	 * @function udp
	 * @tparam[opt] table args arguments
	 * @see UDP:new
	 * @treturn UDP a new UDP Layer object
	 * @within Layers
	 */
	lua_register(l, "udp", l_UDP);
	/***
	 * A default UDP layer whose destination port is 53
	 * @table UDP
	 * @see UDP
	 * @within UDP
	 */
	l_do(l, "UDP=udp({dst=53})");
}
