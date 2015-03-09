#include "lua_ip.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * The IP Layer, inherits from @{Base_Object}
 * @classmod IP
 */
/***
 * Constructor for an IP Layer
 * @function new
 * @tparam[opt] table args arguments, all grouped inside a table, see @{new_args}
 * @treturn IP a new IP object
 * @usage IP.new{
 *	dst="8.8.8.8,
 *	proto=17,
 *	tll=64
 * }
 */
/***
 * Constructor arguments
 * @table new_args
 * @tfield string dst the IP dst
 * @tfield num id the IP identifier
 * @tfield num flags the IP flags
 * @tfield num ttl the IP TTL
 * @tfield num offset the IP fragment offset
 * @tfield num ecn the IP ecn flag
 * @tfield num dscp the IP dscp byte
 * @tfield num proto the IP protocol number
 */

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
	meta_bind_func(l, "new", l_IP);
	/***
	 * Set the IP source address
	 * @function source
	 * @tparam string source the IP source address
	 * */
	meta_bind_func(l, "source", L_SETTER(string, IP, SourceIP));
	/***
	 * Set the IP destination address
	 * @function dest
	 * @tparam string dest the IP destination address
	 * */
	meta_bind_func(l, "dest", L_SETTER(string, IP, DestinationIP));
	/***
	 * Set the IP flags
	 * @function flags
	 * @tparam num flags
	 * */
	meta_bind_func(l, "flags", L_SETTER(word, IP, Flags));
	/***
	 * Set the IP fragment offset
	 * @function fragoffset
	 * @tparam num offset
	 * */
	meta_bind_func(l, "fragoffset", L_SETTER(word, IP, FragmentOffset));
	/***
	 * Set the IP TTL
	 * @function ttl
	 * @tparam num tll
	 * */
	meta_bind_func(l, "ttl", L_SETTER(byte, IP, TTL));
	/***
	 * Set the IP Identification
	 * @function id
	 * @tparam num id
	 * */
	meta_bind_func(l, "id", L_SETTER(short_word, IP, Identification));
	/***
	 * Set the IP DSCP
	 * @function dscp
	 * @tparam num dscp
	 * */
	meta_bind_func(l, "dscp", L_SETTER(word, IP, DiffServicesCP));
	/***
	 * Set the IP ECN
	 * @function ecn
	 * @tparam num ecn
	 * */
	meta_bind_func(l, "ecn", L_SETTER(word, IP, ExpCongestionNot));
}
