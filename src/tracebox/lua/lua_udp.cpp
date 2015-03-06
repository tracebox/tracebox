#include "lua_udp.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_udp_ref::l_UDP(lua_State *l)
{
	UDP *udp;
	int src, dst;
	bool src_set = v_arg_integer_opt(l, 1, "src", &src);
	bool dst_set = v_arg_integer_opt(l, 1, "dst", &dst);

	udp = l_udp_ref::new_ref(l);
	if (!udp)
		return 0;

	udp->SetSrcPort(src_set ? src : rand() % USHRT_MAX);
	udp->SetSrcPort(dst_set ? dst : rand() % USHRT_MAX);
	return 1;
}

void l_udp_ref::register_members(lua_State *l)
{
	l_layer_ref<UDP>::register_members(l);
	meta_bind_func(l, "source", L_SETTER(short_word, UDP, SrcPort));
	meta_bind_func(l, "dest", L_SETTER(short_word, UDP, DstPort));
}

void l_udp_ref::register_globals(lua_State *l)
{
	l_layer_ref<UDP>::register_globals(l);
	lua_register(l, "udp", l_UDP);
	l_do(l, "UDP=udp({dst=53})");
}
