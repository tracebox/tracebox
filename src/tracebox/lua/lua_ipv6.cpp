#include "lua_ipv6.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * The IPv6 Layer, inherits from @{Base_Object}
 * @classmod IPv6
 */
/***
 * Constructor for an IPv6 Layer
 * @function new
 * @tparam[opt] table args arguments, all grouped inside a table, see @{new_args}
 * @treturn IPv6 a new IPv6 object
 * @usage IPv6.new{
 *	dst="2001:db8:1234::1",
 *	hoplimit=4
 * }
 */
/***
 * Constructor arguments
 * @table new_args
 * @tfield string dst the IPv6 dst
 * @tfield num tc the IPv6 traffic class
 * @tfield num flowlabel the IPv6 flowlabel
 * @tfield num hoplimit the IPv6 hop limit
 */

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
	meta_bind_func(l, "new", l_IPv6);
	/***
	 * Set the source address
	 * @function source
	 * @tparam string ip
	 */
	meta_bind_func(l, "source", L_SETTER(string, IPv6, SourceIP));
	/***
	 * Set the destination address
	 * @function dest
	 * @tparam string ip
	 */
	meta_bind_func(l, "dest", L_SETTER(string, IPv6, DestinationIP));
	/***
	 * Set the traffic class
	 * @function tc
	 * @tparam num tc
	 */
	meta_bind_func(l, "tc", L_SETTER(word, IPv6, TrafficClass));
	/***
	 * Set the flow label
	 * @function flowlabel
	 * @tparam num flowlabel
	 */
	meta_bind_func(l, "flowlabel", L_SETTER(word, IPv6, FlowLabel));
	/***
	 * Set the hop limit (=TTL)
	 * @function hoplimit
	 * @tparam num hops
	 */
	meta_bind_func(l, "hoplimit", L_SETTER(byte, IPv6, HopLimit));
}
