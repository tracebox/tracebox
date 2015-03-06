#include "lua_tcp.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_tcp_ref::l_TCP(lua_State *l)
{
	TCP *tcp;
	int src, dst, seq, ack, win, flags;
	bool src_set = v_arg_integer_opt(l, 1, "src", &src);
	bool dst_set = v_arg_integer_opt(l, 1, "dst", &dst);
	bool seq_set = v_arg_integer_opt(l, 1, "seq", &seq);
	bool ack_set = v_arg_integer_opt(l, 1, "ack", &ack);
	bool win_set = v_arg_integer_opt(l, 1, "win", &win);
	bool flags_set = v_arg_integer_opt(l, 1, "flags", &flags);

	tcp = l_tcp_ref::new_ref(l);
	if (!tcp)
		return 0;
	tcp->SetSrcPort(src_set ? src : rand() % USHRT_MAX);
	tcp->SetDstPort(dst_set ? dst : rand() % USHRT_MAX);
	tcp->SetSeqNumber(seq_set ? seq : rand() % UINT_MAX);
	if (ack_set)
		tcp->SetAckNumber(ack);
	if (win_set)
		tcp->SetWindowsSize(win);
	tcp->SetFlags(flags_set ? flags : TCP::SYN);
	return 1;
}

void l_tcp_ref::register_members(lua_State *l)
{
	l_layer_ref<TCP>::register_members(l);
	META_GETTER_SETTER(l, source, short_word,  TCP, SrcPort);
	META_GETTER_SETTER(l, dest,   short_word,  TCP, DstPort);
	META_GETTER_SETTER(l, seq,    word,        TCP, SeqNumber);
	META_GETTER_SETTER(l, ack,    word,        TCP, AckNumber);
	META_GETTER_SETTER(l, win,    short_word,  TCP, WindowsSize);
	META_GETTER_SETTER(l, flags,  byte,        TCP, Flags);
}

void l_tcp_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCP>::register_globals(l);
	lua_register(l, "tcp", l_TCP);
	l_do(l, "TCP=tcp({dst=80})");
}
