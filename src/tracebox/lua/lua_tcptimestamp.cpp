#include "lua_tcptimestamp.h"
#include "lua_arg.h"

using namespace Crafter;

/***
 * The TCP Timestamp option
 * @classmod TCPTimestamp
 */
/***
 * Create a new Timestamp Option
 * @function new
 * @tparam[opt] table args the timestamp options, see @{new_args}
 * @treturn TCPTimestamp
 */
/***
 * The Timestamp Option arguments
 * @table new_args
 * @tfield num val the timestamp value
 * @tfield num ecr the timestamp echo value
 */
int l_tcptsopt_ref::l_TCP_Timestamp(lua_State *l)
{
	TCPOptionTimestamp *opt;
	int val, ecr;
	bool val_set = v_arg_integer_opt(l, 1, "val", &val);
	bool ecr_set = v_arg_integer_opt(l, 1, "ecr", &ecr);

	opt = l_tcptsopt_ref::new_ref(l);
	if (!opt)
		return 0;

	opt->SetValue(val_set ? val : rand() % UINT_MAX);
	opt->SetEchoReply(ecr_set ? ecr : 0);

	return 1;
}

void l_tcptsopt_ref::register_members(lua_State *l)
{
	l_layer_ref<TCPOptionTimestamp>::register_members(l);
	/***
	 * Get/Set the Echo Reply field in the timestamp
	 * @function ecr
	 * @tparam[opt] num ecr Set the ecr value
	 * @treturn num ecr
	 */
	meta_bind_func(l, "ecr", L_ACCESSOR(word, TCPOptionTimestamp, EchoReply));
	/***
	 * Get/Set the Value field in the timestamp
	 * @function val
	 * @tparam[opt] num val Set the timestamp value
	 * @treturn num val
	 */
	meta_bind_func(l, "val", L_ACCESSOR(word, TCPOptionTimestamp, Value));
}
