/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "config.h"

#include "lua_base.hpp"
#include "lua_crafter.hpp"
#include "lua_dns.h"
#include "lua_fwfilter.h"
#include "lua_icmp.h"
#include "lua_ip.h"
#include "lua_ipoption.hpp"
#include "lua_ipv6.h"
#include "lua_ipv6segmentroutingheader.h"
#include "lua_packet.hpp"
#include "lua_packetmodifications.h"
#include "lua_partialtcp.h"
#include "lua_raw.h"
#include "lua_tcp.h"
#include "lua_tcpoption.hpp"
#include "lua_tcptimestamp.h"
#include "lua_tcpedo.h"
#include "lua_tcptfo.h"
#include "lua_udp.h"

#ifdef HAVE_SNIFFER
#include "lua_sniffer.h"
#endif

/*
 * 1. Create & fill associated metatable
 * 2 Register globals functions/values for that type
 */
#define _INIT_TYPE_START(ref_t, t, l) \
	do { \
	const char *n = TNAME(t); \
	luaL_newmetatable(l, n); \
	ref_t::register_members(l); \
	lua_pushvalue(l, -1); \
	lua_setfield(l, -1, "__index"); \
	lua_setglobal(l,  n); \
	ref_t::register_globals(l);

#define _INIT_TYPE_END } while(0)

#define INIT_TYPE(ref_t, t, l) \
	_INIT_TYPE_START(ref_t, t, l) \
	_INIT_TYPE_END

#define INIT_LAYER(ref_t, t, l) \
	_INIT_TYPE_START(ref_t, t, l) \
	lua_tbx::l_layer_ref_mapping->insert({t::PROTO, TNAME(t)}); \
	_INIT_TYPE_END


/* We might want to stop using globals and instead do a global table,
 * this hook will allow for an easier transition */
#define REGISTER_FUNCTION(l, name, func) lua_register(l, name, func)

using namespace Crafter;

/* Populate the tname<x> template */
L_EXPOSE_TYPE(IP);
L_EXPOSE_TYPE(IPv6);
L_EXPOSE_TYPE(IPv6SegmentRoutingHeader);
L_EXPOSE_TYPE(TCP);
L_EXPOSE_TYPE_AS(TCPOptionTimestamp, TCPTimestamp);
L_EXPOSE_TYPE_AS(TCPOptionFastOpen, TCPTFO);
L_EXPOSE_TYPE_AS(TCPOptionEDO, TCPEDO);
L_EXPOSE_TYPE(UDP);
L_EXPOSE_TYPE(ICMP);
L_EXPOSE_TYPE(RawLayer);
L_EXPOSE_TYPE(DNS);
L_EXPOSE_TYPE(PartialTCP);
L_EXPOSE_TYPE(Layer);
L_EXPOSE_TYPE(Packet);
L_EXPOSE_TYPE_AS(TCPOptionLayer, TCPOption);
L_EXPOSE_TYPE(FWFilter);
L_EXPOSE_TYPE(PacketModifications);
L_EXPOSE_TYPE_AS(DNS::DNSQuery, DNSQuery);
L_EXPOSE_TYPE_AS(DNS::DNSAnswer, DNSAnswer);
L_EXPOSE_TYPE_AS(IPOptionLayer, IPOption);
#ifdef HAVE_SNIFFER
L_EXPOSE_TYPE(TbxSniffer);
#endif

/* lua_tracebox.cpp */
extern int l_Tracebox(lua_State *l);
extern int l_set_ttl_range(lua_State *);
/* lua_utils.cpp */
extern int l_sleep(lua_State *l);
extern int l_dump_stack(lua_State *l);
extern int l_dn6(lua_State *l);
extern int l_dn4(lua_State *l);
extern int l_gethostname(lua_State *l);
extern int l_random(lua_State *l);

lua_State *l_init()
{
	lua_State * l = luaL_newstate();
	luaL_openlibs(l);
	/* Create types metatables */
	INIT_TYPE(l_packet_ref,                    Packet,                   l);
	INIT_LAYER(l_ip_ref,                        IP,                       l);
	INIT_TYPE(l_ipoption_ref,                  IPOptionLayer,            l);
	INIT_LAYER(l_ipv6_ref,                      IPv6,                     l);
	INIT_LAYER(l_ipv6segmentroutingheader_ref,  IPv6SegmentRoutingHeader, l);
	INIT_LAYER(l_tcp_ref,                       TCP,                      l);
	INIT_TYPE(l_tcpoption_ref,                 TCPOptionLayer,           l);
	INIT_LAYER(l_tcptsopt_ref,                  TCPOptionTimestamp,       l);
	INIT_LAYER(l_tcptfo_ref,                    TCPOptionFastOpen,        l);
	INIT_LAYER(l_tcpedoopt_ref,                 TCPOptionEDO,             l);
	INIT_LAYER(l_udp_ref,                       UDP,                      l);
	INIT_LAYER(l_icmp_ref,                      ICMP,                     l);
	INIT_LAYER(l_raw_ref,                       RawLayer,                 l);
	INIT_LAYER(l_dns_ref,                       DNS,                      l);
	INIT_TYPE(l_packetmodifications_ref,       PacketModifications,      l);
	INIT_TYPE(l_fwfilter_ref,                  FWFilter,                 l);
	INIT_TYPE(l_dnsquery_ref,                  DNS::DNSQuery,            l);
	INIT_TYPE(l_dnsanswer_ref,                 DNS::DNSAnswer,           l);
	#ifdef HAVE_SNIFFER
	INIT_TYPE(l_sniffer_ref,                   TbxSniffer,               l);
	#endif
	INIT_LAYER(l_partialtcp_ref, PartialTCP, l);

	REGISTER_FUNCTION(l, "tracebox", l_Tracebox);
	REGISTER_FUNCTION(l, "sleep", l_sleep);
	REGISTER_FUNCTION(l, "dn4", l_dn4);
	REGISTER_FUNCTION(l, "dn6", l_dn6);
	REGISTER_FUNCTION(l, "gethostname", l_gethostname);
	REGISTER_FUNCTION(l, "__dump_c_stack", l_dump_stack);
	REGISTER_FUNCTION(l, "random", l_random);
	REGISTER_FUNCTION(l, "set_ttl_range", l_set_ttl_range);

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
	l_do(l, "IP=ip({id=math.random(65535)})");
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
	 * @table IP_NOP
	 * @see IPOption
	 * @within IP
	 */
	l_do(l, "IP_NOP=ip_nop()");
	/***
	 * A default IP EOL object
	 * @table IP_EOL
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
	l_do(l, "IPv6=ipv6({flowlabel=math.random(1048575)})");
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

void l_tcpedoopt_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCPOptionEDO>::register_globals(l);
	/***
	 * Construct a  TCPOption EDO, shorthand for @{TCPEDO:new}
	 * @function edo
	 * @treturn TCPEDO
	 * @see TCPEDO:new
	 * @within TCP
	 */
	lua_register(l, "edo", l_TCP_EDO);
	/***
	 * A TCPEDO option that will contain the header length field
	 * @table EDO
	 * @see TCPEDO:new
	 * @within TCP
	 */
	l_do(l, "EDO=edo(TCPEDO.EDO)");
	/***
	 * A TCPEDO option to be used during the handshake negociation,
	 * requires padding (length is 2 bytes)
	 * @table EDOREQUEST
	 * @see TCPEDO:new
	 * @within TCP
	 */
	l_do(l, "EDOREQUEST=edo(TCPEDO.EDOREQUEST)");
	/***
	 * A TCPEDO option containing the header length and the segment length,
	 * requires padding (length is 6 bytes)
	 * @table EDOEXT
	 * @see TCPEDO:new
	 * @within TCP
	 */
	l_do(l, "EDOEXT=edo(TCPEDO.EDOEXT)");
}

void l_tcptsopt_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCPOptionTimestamp>::register_globals(l);
	/***
	 * Construct a  TCPOption Timestamp, shorthand for @{TCPTimestamp:new}
	 * @function timestamp
	 * @tparam[opt] table arg
	 * @treturn TCPTimestamp
	 * @see TCPTimestamp:new
	 * @within TCP
	 */
	lua_register(l, "timestamp", l_TCP_Timestamp);
	/***
	 * A default TCP Timestamp object
	 * @table TS
	 * @see TCPTimestamp:new
	 * @within TCP
	 */
	l_do(l, "TS=NOP/NOP/timestamp{}");
}

void l_tcptfo_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCPOptionFastOpen>::register_globals(l);
	/***
	 * Construct a  TCPOption TFO, shorthand for @{TCPTFO:new}
	 * @function tfo
	 * @tparam[opt] table cookie
	 * @treturn TCPTFO
	 * @see TCPTFO:new
	 * @within TCP
	 */
	lua_register(l, "tfo", l_TCP_TFO);
	/***
	 * A default TCP TFO object
	 * @table TFO
	 * @see TCPTFO:new
	 * @within TCP
	 */
	l_do(l, "TFO=NOP/NOP/tfo{}");
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

/***
 * @section DNS
 */
void l_dnsquery_ref::register_globals(lua_State *l)
{
	l_ref<DNS::DNSQuery>::register_globals(l);
	/***
	 * Create a new DNSQuery for a given hostname, type A, class IN
	 * @function dnsquery
	 * @tparam string name
	 * @treturn DNSQuery
	 */
	l_do(l, "function dnsquery(n) return DNSQuery.new{"
			"name=n, type=DNS.Type.A, class=DNS.Class.IN} end");
}

/***
 * @section TbxSniffer
 */
#ifdef HAVE_SNIFFER
void l_sniffer_ref::register_globals(lua_State *l)
{
	l_ref<TbxSniffer>::register_globals(l);
	/***
	 * Create a TbxSniffer and start sniffing immediately
	 * @function snif
	 * @tparam table key the Sniffing key
	 * @tparam function cb the callback function
	 * @see TbxSniffer:new
	 * @within TbxSniffer
	 */
	l_do(l, "function snif(key, cb) _sniffer=TbxSniffer.new(key)"
			"\n _sniffer:start(cb) end");
}
#endif
