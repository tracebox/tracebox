/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_partialtcp.h"

using namespace Crafter;
using namespace std;

/***
 * The PartialTCP Layer, inherits from @{Base_Object}
 * This denotes a embedded TCP layer in an ICMP payload that has been cut.
 * As such, it cannot be constructed directly.
 * @classmod PartialTCP
 */

void l_partialtcp_ref::register_members(lua_State *l)
{
	l_layer_ref<UDP>::register_members(l);
	/***
	 * Get the TCP source port
	 * @function getsource
	 * */
	meta_bind_func(l, "getsource", L_GETTER(short_word, PartialTCP, SrcPort));
	/***
	 * Get the TCP destination port
	 * @function getdst
	 * */
	meta_bind_func(l, "getdst", L_GETTER(short_word, PartialTCP, DstPort));
	/***
	 * Get the TCP sequence number
	 * @function getseq
	 * */
	meta_bind_func(l, "getseq", L_GETTER(word, PartialTCP, SeqNumber));
}
