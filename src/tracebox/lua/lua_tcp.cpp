/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_tcp.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * The TCP Layer, inherits from @{Base_Object}
 * @classmod TCP
 */
/***
 * Constructor for a TCP Layer
 * @function new
 * @tparam[opt] table args arguments, all grouped inside a table, see @{new_args}
 * @treturn TCP a new TCP object
 * @usage TCP.new{
 * 	 dst=80,
 * 	 flags=18
 * }
 */
/***
 * Constructor arguments
 * @table new_args
 * @tfield num src the source port
 * @tfield num dst the destination port
 * @tfield num seq the sequence number
 * @tfield num ack the acknowledgment number
 * @tfield num win the window size
 * @tfield num flags the flags (all at once)
 */
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

/***
 * Check if the TCP Layer has the given flag combination
 * @function hasflags
 * @tparam num flags a flag mask
 * @treturn num r 0 if the layer doesn't have the flags
 * @usage tcp:hasflags(TCP.SYN + TCP.ACK)
 */
int l_tcp_ref::l_hasflags(lua_State *l)
{
	TCP *tcp = l_tcp_ref::get(l, 1);
	int flags = l_data_type<int>::get(l, 2);
	l_data_type<int>(tcp->GetFlags() & flags).push(l);
	return 1;
}

void l_tcp_ref::register_members(lua_State *l)
{
	l_layer_ref<TCP>::register_members(l);
	meta_bind_func(l, "new", l_TCP);
	meta_bind_func(l, "hasflags", l_hasflags);
	/***
	 * Get the TCP data offset value
	 * @function offset
	 * @treturn num offset
	 */
	meta_bind_func(l, "offset", L_GETTER(word, TCP, DataOffset));
	/***
	 * Set the TCP source port
	 * @function setsource
	 * @tparam num source the TCP source port
	 * */
	/***
	 * Get the TCP source port
	 * @function getsource
	 * @treturn num source the TCP source port
	 * */
	META_GETTER_SETTER(l, source, short_word,  TCP, SrcPort);
	/***
	 * Set the TCP destination port
	 * @function sedest
	 * @tparam num dest the TCP destination port
	 * */
	/***
	 * Get the TCP destination port
	 * @function gedest
	 * @treturn num dest the TCP destination port
	 * */
	META_GETTER_SETTER(l, dest,   short_word,  TCP, DstPort);
	/***
	 * Set the TCP sequence number
	 * @function setseq
	 * @tparam num seq the TCP sequence number
	 * */
	/***
	 * Get the TCP sequence number
	 * @function getseq
	 * @treturn num seq the TCP sequence number
	 * */
	META_GETTER_SETTER(l, seq,    word,        TCP, SeqNumber);
	/***
	 * Set the TCP acknowledgment number
	 * @function setack
	 * @tparam num ack the TCP acknowledgment number
	 * */
	/***
	 * Get the TCP acknowledgment number
	 * @function getack
	 * @treturn num ack the TCP acknowledgment number
	 * */
	META_GETTER_SETTER(l, ack,    word,        TCP, AckNumber);
	/***
	 * Set the TCP window size
	 * @function setwin
	 * @tparam num win the TCP window size
	 * */
	/***
	 * Get the TCP window size
	 * @function getwin
	 * @treturn num win the TCP window size
	 * */
	META_GETTER_SETTER(l, win,    short_word,  TCP, WindowsSize);
	/***
	 * Set the TCP flags
	 * @function setflags
	 * @tparam num flags the TCP flags
	 * @usage tcp:setflags(TCP.SYN + TCP.ACK)
	 * */
	/***
	 * Get the TCP flags
	 * @function getflags
	 * @treturn num flags the TCP flags
	 * */
	META_GETTER_SETTER(l, flags,  byte,        TCP, Flags);
	#define META_FLAG(f) metatable_bind(l, #f, l_data_type<int>(TCP::f))
	/***
	 * The TCP FIN flag value
	 * @tfield num FIN
	 */
	META_FLAG(FIN);
	/***
	 * The TCP SYN flag value
	 * @tfield num SYN
	 */
	META_FLAG(SYN);
	/***
	 * The TCP RST flag value
	 * @tfield num RST
	 */
	META_FLAG(RST);
	/***
	 * The TCP PSH flag value
	 * @tfield num PSH
	 */
	META_FLAG(PSH);
	/***
	 * The TCP ACK flag value
	 * @tfield num ACK
	 */
	META_FLAG(ACK);
	/***
	 * The TCP URG flag value
	 * @tfield num URG
	 */
	META_FLAG(URG);
	/***
	 * The TCP ECE flag value
	 * @tfield num ECE
	 */
	META_FLAG(ECE);
	/***
	 * The TCP CWR flag value
	 * @tfield num CWR
	 */
	META_FLAG(CWR);
}
