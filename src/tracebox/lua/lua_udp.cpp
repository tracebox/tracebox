#include "lua_udp.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * The UDP Layer, inherits from @{Base_Object}
 * @classmod UDP
 */
/***
 * Constructor for an UDP Layer
 * @function new
 * @tparam[opt] table args arguments, all grouped inside a table, see @{new_args}
 * @treturn UDP a new UDP object
 * @usage UDP.new{ dst=53 }
 * */
/***
 * Constructor arguments
 * @table new_args
 * @tfield num src the source port
 * @tfield num dst the destination port
 */
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
	meta_bind_func(l, "new", l_UDP);
	/***
	 * Set the UDP source port
	 * @function source
	 * @tparam num source port number
	 * */
	meta_bind_func(l, "source", L_SETTER(short_word, UDP, SrcPort));
	/***
	 * Set the UDP destination port
	 * @function dest
	 * @tparam num dest destination port number
	 * */
	meta_bind_func(l, "dest", L_SETTER(short_word, UDP, DstPort));
}
