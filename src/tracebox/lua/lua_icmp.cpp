#include "lua_icmp.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * The ICMP Layer, inherits from @{Base_Object}
 * @classmod ICMP
 */
/***
 * Constructor for an ICMP Layer
 * @function new
 * @tparam[opt] table args arguments, all grouped inside a table, see @{new_args}
 * @treturn ICMP a new ICMP object
 * @usage ICMP.new{
 *   type=1,
 *   code=2,
 *   id=37,
 *   seqno=17
 * }
 */
/***
 * Constructor arguments
 * @table new_args
 * @tfield num type the ICMP type
 * @tfield num code the ICMP code
 * @tfield num id the ICMP identifier
 * @tfield num seqno the ICMP seq. number
 * @tfield num ptr the ICMP pointer
 * @tfield num len the ICMP length
 * @tfield num mtu the ICMP mtu
 * @tfield string gw the ICMP gateway
 */
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
	meta_bind_func(l, "new", l_ICMP);
	/***
	 * Set the ICMP type
	 * @function type
	 * @tparam num type
	 * */
	meta_bind_func(l, "type", L_SETTER(byte, ICMP, Type));
	/***
	 * Set the ICMP code
	 * @function code
	 * @tparam num code
	 * */
	meta_bind_func(l, "code", L_SETTER(byte, ICMP, Code));
	/***
	 * Set the ICMP identifier
	 * @function id
	 * @tparam num id
	 * */
	meta_bind_func(l, "id", L_SETTER(short_word, ICMP, Identifier));
	/***
	 * Set the ICMP sequence number
	 * @function seqno
	 * @tparam num seqno
	 * */
	meta_bind_func(l, "seqno", L_SETTER(short_word, ICMP, SequenceNumber));
	/***
	 * Set the ICMP pointer
	 * @function ptr
	 * @tparam num ptr
	 * */
	meta_bind_func(l, "ptr", L_SETTER(byte, ICMP, Pointer));
	/***
	 * Set the ICMP gateway
	 * @function gw
	 * @tparam string gw the IP address of the gateway
	 * */
	meta_bind_func(l, "gw", L_SETTER(string, ICMP, Gateway));
	/***
	 * Set the ICMP length
	 * @function len
	 * @tparam num len
	 * */
	meta_bind_func(l, "len", L_SETTER(byte, ICMP, Length));
	/***
	 * Set the ICMP MTU
	 * @function mtu
	 * @tparam num mtu
	 * */
	meta_bind_func(l, "mtu", L_SETTER(short_word, ICMP, MTU));
}

