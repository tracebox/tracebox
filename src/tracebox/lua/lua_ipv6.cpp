#include "lua_ipv6.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_ipv6_ref::l_IPv6(lua_State *l)
{
	IPv6 *ipv6;

	const char *dst;
	int tc, flabel, hoplimit;
	bool dst_set = v_arg_string_opt(l, 1, "dst", &dst);
	bool tc_set = v_arg_integer_opt(l, 1, "tc", &tc);
	bool flabel_set = v_arg_integer_opt(l, 1, "flowlabel", &flabel);
	bool hoplimit_set = v_arg_integer_opt(l, 1, "hoplimit", &hoplimit);

	ipv6 = l_ipv6_ref::new_ref(l);
	if (!ipv6)
		return 0;

	if (dst_set)
		ipv6->SetDestinationIP(dst);
	if (tc_set)
		ipv6->SetTrafficClass(tc);
	if (hoplimit_set)
		ipv6->SetHopLimit(hoplimit);
	if (flabel_set)
		ipv6->SetFlowLabel(flabel);
	return 1;
}

void l_ipv6_ref::register_members(lua_State *l)
{
	l_layer_ref<IPv6>::register_members(l);
	meta_bind_func(l, "source", L_SETTER(string, IPv6, SourceIP));
	meta_bind_func(l, "dest", L_SETTER(string, IPv6, DestinationIP));
	meta_bind_func(l, "tc", L_SETTER(word, IPv6, TrafficClass));
	meta_bind_func(l, "flowlabel", L_SETTER(word, IPv6, FlowLabel));
	meta_bind_func(l, "hoplimit", L_SETTER(byte, IPv6, HopLimit));
}

void l_ipv6_ref::register_globals(lua_State *l)
{
	l_layer_ref<IPv6>::register_globals(l);
	lua_register(l, "ipv6", l_IPv6);
	l_do(l, "IPv6=ipv6({})");
}
