#include "lua_tcpoption.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * Options for the TCP Layer, inherits from @{Base_Object}
 * @classmod TCPOption
 */
/***
 * Create a new NOP Option (Kind=1)
 * @function new_nop
 * @treturn TCPOption
 */
int l_tcpoption_ref::l_TCP_NOP(lua_State *l)
{
	TCPOptionPad *opt = l_tcpoption_ref::new_option_ref<TCPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetKind(1);
	return 1;
}

/***
 * Create a new EOL Option (Kind=0)
 * @function new_eol
 * @treturn TCPOption
 */
int l_tcpoption_ref::l_TCP_EOL(lua_State *l)
{
	TCPOptionPad *opt = l_tcpoption_ref::new_option_ref<TCPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetKind(0);
	return 1;
}

/***
 * Create a new SACKPermitted Option
 * @function new_sackp
 * @treturn TCPOption
 */
int l_tcpoption_ref::l_TCP_SACKP(lua_State *l)
{
	TCPOptionSACKPermitted *opt = l_tcpoption_ref::new_option_ref<TCPOptionSACKPermitted>(l);
	return opt != NULL;
}

static TCPOptionSACK::Pair extract_pair(lua_State *l, int i)
{
	int left, right;

	// lua_next has already been called
	left = luaL_checknumber(l, -1);
	lua_pop(l, 1);
	lua_next(l, i);
	right = luaL_checknumber(l, -1);
	lua_pop(l, 1);

	return TCPOptionSACK::Pair(left, right);
}

/***
 * Create a new SACK Option
 * @function new_sack
 * @tparam table a list of pairs, either grouped in subtables or in one single flat table
 * @usage l = TCPOption:new_sack{1, 2, 3, 4} -- Will create a SACK option with pairs (1,2) and (3,4)
 * l = TCPOption:new_sack{{1, 2}, {3, 4}} -- Equivalent to the above
 * @treturn TCPOption
 */
int l_tcpoption_ref::l_TCP_SACK(lua_State *l)
{
	TCPOptionSACK *opt;
	std::vector<TCPOptionSACK::Pair> v;

	if (!lua_istable(l, 1)) {
		const char* msg = lua_pushfstring(l, "argument must be a table");
		luaL_argerror(l, 1, msg);
		return 0;
	}
	lua_pushnil(l);
	while (lua_next(l, 1)) {
		int i = lua_gettop(l);

		if (lua_isnumber(l, -1)) {
			v.push_back(extract_pair(l, 1));
		} else if (lua_istable(l, -1)) {
			lua_pushnil(l);
			lua_next(l, i);
			v.push_back(extract_pair(l, i));
			lua_pop(l, 2);
		} else {
			const char* msg = lua_pushfstring(l, "element must be a table");
			luaL_argerror(l, -1, msg);
			return 0;
		}
	}

	opt = l_tcpoption_ref::new_option_ref<TCPOptionSACK>(l);
	if (!opt)
		return 0;

	opt->SetBlocks(v);

	return 1;
}

/***
 * Create a new MSS Option
 * @function new_mss
 * @tparam num the MSS value value
 * @treturn TCPOption
 */
int l_tcpoption_ref::l_TCP_MSS(lua_State *l)
{
	TCPOptionMaxSegSize *opt;
	int mss = luaL_checknumber(l, 1);

	opt = l_tcpoption_ref::new_option_ref<TCPOptionMaxSegSize>(l);
	if (!opt)
		return 0;

	opt->SetMaxSegSize(mss);
	return 1;
}

/***
 * Create a new Timestamp Option
 * @function new_timestamp
 * @tparam[opt] table args the timestamp options, see @{Timestamp_args}
 * @treturn TCPOption
 */
/***
 * The Timestamp Option arguments
 * @see new_timestamp
 * @table Timestamp_args
 * @tfield num val the timestamp value
 * @tfield num ecr the timestamp echo value
 */
int l_tcpoption_ref::l_TCP_Timestamp(lua_State *l)
{
	TCPOptionTimestamp *opt;
	int val, ecr;
	bool val_set = v_arg_integer_opt(l, 1, "val", &val);
	bool ecr_set = v_arg_integer_opt(l, 1, "ecr", &ecr);

	opt = l_tcpoption_ref::new_option_ref<TCPOptionTimestamp>(l);
	if (!opt)
		return 0;

	opt->SetValue(val_set ? val : rand() % UINT_MAX);
	opt->SetEchoReply(ecr_set ? ecr : 0);

	return 1;
}

/***
 * Create a new WindowScale Option
 * @function new_wscale
 * @tparam num wscale the window scaling factor
 * @treturn TCPOption
 */
int l_tcpoption_ref::l_TCP_WindowScale(lua_State *l)
{
	TCPOptionWindowScale *opt;
	const byte shift = luaL_checknumber(l, 1);

	opt = l_tcpoption_ref::new_option_ref<TCPOptionWindowScale>(l);
	if (!opt)
		return 0;

	opt->SetShift(shift);

	return 1;
}

/***
 * Create a new MPTCPJoin Option
 * @function new_mpjoin
 * @tparam[opt] table the MPJoin options, see @{MPJoin_args}
 * @treturn TCPOption
 */
/***
 * The MPTCPJoin Option arguments
 * @see new_mpjoin
 * @table MPJoin_args
 * @tfield num token
 * @tfield num nonce
 * @tfield num id address ID
 * @tfield bool backup
 */
int l_tcpoption_ref::l_TCP_MPTCPJoin(lua_State *l)
{
	TCPOptionMPTCPJoin *opt;
	bool backup = false;
	int token = 0, nonce = 0, addr_id = 1;
	bool token_set = v_arg_integer_opt(l, 1, "token", &token);
	bool nonce_set = v_arg_integer_opt(l, 1, "nonce", &nonce);
	bool addr_id_set = v_arg_integer_opt(l, 1, "id", &addr_id);
	v_arg_boolean_opt(l, 1, "backup", &backup);

	opt = l_tcpoption_ref::new_option_ref<TCPOptionMPTCPJoin>(l);
	if (!opt)
		return 0;

	if (backup)
		opt->EnableBackupPath();

	if (addr_id_set)
		opt->SetAddrID(addr_id);
	opt->SetReceiverToken(token_set ? token : ((uint32_t)rand()) << 16 | rand());
	opt->SetSenderRandomNumber(nonce_set ? nonce : ((uint32_t)rand()) << 16 | rand());

	return 1;
}

/***
 * Create a new MPTCPCapable Option
 * @function new_mpcapable
 * @tparam[opt] table the MPCapable options, see @{MPCapable_args}
 * @treturn TCPOption
 */
/***
 * The MPTCPCapable Option arguments
 * @see new_mpjoin
 * @table MPCapable_args
 * @tfield num skey sender key
 * @tfield num rkey receiver key
 * @tfield bool csum checksum
 */
int l_tcpoption_ref::l_TCP_MPTCPCapable(lua_State *l)
{
	TCPOptionMPTCPCapable *opt;
	uint64_t skey, rkey;
	bool csum = true; /* enable by default */
	bool skey_set = v_arg_integer64_opt(l, 1, "skey", &skey);
	bool rkey_set = v_arg_integer64_opt(l, 1, "rkey", &rkey);
	v_arg_boolean_opt(l, 1, "csum", &csum);

	opt = l_tcpoption_ref::new_option_ref<TCPOptionMPTCPCapable>(l);
	if (!opt)
		return 0;

	if (csum)
		opt->EnableChecksum();
	opt->SetSenderKey(skey_set ? skey : ((uint64_t)rand()) << 32 | rand());
	if (rkey_set)
		opt->SetReceiverKey(rkey);
	return 1;
}

void l_tcpoption_ref::register_members(lua_State *l)
{
	l_layer_ref<TCPOptionLayer>::register_members(l);
	/***
	 * Set the Option Kind
	 * @function kind
	 * @tparam num kind
	 */
	meta_bind_func(l, "kind", L_SETTER(byte, TCPOptionLayer, Kind));
	/***
	 * Set the Option data (raw access)
	 * @function data
	 * @tparam string data
	 */
	meta_bind_func(l, "data", set_payload<TCPOptionLayer>);
}
