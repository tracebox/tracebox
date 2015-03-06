#include "lua_ip.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_ip_ref::l_IP(lua_State *l)
{
	IP *ip;
	const char *dst;
	int id, flags, ttl, dscp, fragoffset, ecn, proto;
	bool dst_set = v_arg_string_opt(l, 1, "dst", &dst);
	bool id_set = v_arg_integer_opt(l, 1, "id", &id);
	bool flags_set = v_arg_integer_opt(l, 1, "flags", &flags);
	bool ttl_set = v_arg_integer_opt(l, 1, "ttl", &ttl);
	bool fragoffset_set = v_arg_integer_opt(l, 1, "offset", &fragoffset);
	bool ecn_set = v_arg_integer_opt(l, 1, "ecn", &ecn);
	bool dscp_set = v_arg_integer_opt(l, 1, "dscp", &dscp);
	bool proto_set = v_arg_integer_opt(l, 1, "proto", &proto);

	ip = l_ip_ref::new_ref(l);
	if (!ip)
		return 0;
	if (dst_set)
		ip->SetDestinationIP(dst);
	if (id_set)
		ip->SetIdentification(id);
#ifdef __APPLE__
	else /* FreeBSD add random IP ID if not set */
		ip->SetIdentification(rand() % USHRT_MAX);
#endif
	if (ttl_set)
		ip->SetTTL(ttl);
	if (flags_set)
		ip->SetFlags(flags);
	if (fragoffset_set)
		ip->SetFragmentOffset(fragoffset);
	if (ecn_set)
		ip->SetExpCongestionNot(ecn);
	if (dscp_set)
		ip->SetDiffServicesCP(dscp);
	if (proto_set)
		ip->SetProtocol(proto);
	return 1;
}

void l_ip_ref::register_members(lua_State *l)
{
	l_layer_ref<IP>::register_members(l);
	meta_bind_func(l, "source", L_SETTER(string, IP, SourceIP));
	meta_bind_func(l, "dest", L_SETTER(string, IP, DestinationIP));
	meta_bind_func(l, "flags", L_SETTER(word, IP, Flags));
	meta_bind_func(l, "fragoffset", L_SETTER(word, IP, FragmentOffset));
	meta_bind_func(l, "ttl", L_SETTER(byte, IP, TTL));
	meta_bind_func(l, "id", L_SETTER(short_word, IP, Identification));
	meta_bind_func(l, "dscp", L_SETTER(word, IP, DiffServicesCP));
	meta_bind_func(l, "ecn", L_SETTER(word, IP, ExpCongestionNot));
}

void l_ip_ref::register_globals(lua_State *l)
{
	l_layer_ref<IP>::register_globals(l);
	lua_register(l, "ip", l_IP);
	l_do(l, "IP=ip({})");
}
