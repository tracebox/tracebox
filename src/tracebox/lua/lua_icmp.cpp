#include "lua_icmp.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_icmp_ref::l_ICMP(lua_State *l)
{
	ICMP *icmp;
	const char *gw;
	int code, id, seqno, ptr, len, mtu;
	int type = v_arg_integer(l, 1, "type");
	bool code_set = v_arg_integer_opt(l, 1, "code", &code);
	bool id_set = v_arg_integer_opt(l, 1, "id", &id);
	bool seqno_set = v_arg_integer_opt(l, 1, "seqno", &seqno);
	bool ptr_set = v_arg_integer_opt(l, 1, "ptr", &ptr);
	bool len_set = v_arg_integer_opt(l, 1, "len", &len);
	bool mtu_set = v_arg_integer_opt(l, 1, "mtu", &mtu);
	bool gw_set = v_arg_string_opt(l, 1, "gw", &gw);

	icmp = l_icmp_ref::new_ref(l);
	if (!icmp)
		return 0;

	icmp->SetType(type);
	if (code_set)
		icmp->SetCode(code);
	if (id_set)
		icmp->SetIdentifier(id);
	if (seqno_set)
		icmp->SetSequenceNumber(seqno);
	if (ptr_set)
		icmp->SetPointer(ptr);
	if (len_set)
		icmp->SetLength(len);
	if (mtu_set)
		icmp->SetMTU(mtu);
	if (gw_set)
		icmp->SetGateway(gw);
	return 1;
}

void l_icmp_ref::register_members(lua_State *l)
{
	l_layer_ref<ICMP>::register_members(l);
	meta_bind_func(l, "type", L_SETTER(byte, ICMP, Type));
	meta_bind_func(l, "code", L_SETTER(byte, ICMP, Code));
	meta_bind_func(l, "id", L_SETTER(short_word, ICMP, Identifier));
	meta_bind_func(l, "seqno", L_SETTER(short_word, ICMP, SequenceNumber));
	meta_bind_func(l, "ptr", L_SETTER(byte, ICMP, Pointer));
	meta_bind_func(l, "gw", L_SETTER(string, ICMP, Gateway));
	meta_bind_func(l, "len", L_SETTER(byte, ICMP, Length));
	meta_bind_func(l, "mtu", L_SETTER(short_word, ICMP, MTU));
}

void l_icmp_ref::register_globals(lua_State *l)
{
	l_layer_ref<ICMP>::register_globals(l);
	lua_register(l, "icmp", l_ICMP);
	l_do(l, "function ICMPEchoReq(id,seq) return icmp{type=8,id=id,seqno=seq} end");
	l_do(l, "function ICMPEchoRep(id,seq) return icmp{type=0,id=id,seqno=seq} end");
	l_do(l, "function ICMPDstUnreach(mtu) return icmp{type=3,mtu=mtu} end");
	l_do(l, "ICMPSrcQuench=icmp{type=4}");
	l_do(l, "function ICMPRedirect(addr) return icmp{type=5,gw=addr} end");
	l_do(l, "ICMPTimeExceeded=icmp{type=11}");
}
