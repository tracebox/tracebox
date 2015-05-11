/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_tcpoption.hpp"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * Options for the TCP Layer, inherits from @{Base_Object}
 * @classmod TCPOption
 */
/***
 * Create a 'blank' TCPOption
 * @function new
 * @tparam[opt] table args see @{new_args}
 * @treturn TCPOption
 */
/***
 * TCPOption constructor arguments
 * @table new_args
 * @tfield num copy
 * @tfield num length
 * @tfield table data opaque list of bytes
 */
int l_tcpoption_ref::l_TCPOption(lua_State *l)
{
	uint64_t kind, length;
	bool ki = v_arg_integer64_opt(l, 1, "kind", &kind);
	bool le = v_arg_integer64_opt(l, 1, "length", &length);
	TCPOption *opt = new TCPOption();

	if (ki) opt->SetKind(kind);
	if (le) opt->SetLength(length);
	if (v_arg(l, 1, "data")) {
		std::vector<byte> data;
		luaL_checktype(l, -1, LUA_TTABLE);
		for (int i = 1;; ++i, lua_pop(l, 1)) {
			lua_rawgeti(l, -1, i);
			if (lua_isnil(l, -1)) {
				lua_pop(l, 1);
				break;
			}
			data.push_back(lua_tointeger(l, -1));
		}
		opt->SetPayload(&data[0], data.size());
	}

	new l_tcpoption_ref(opt, l);
	return 1;
}
/***
 * Set the Option Kind
 * @function kind
 * @tparam num kind
 */
/***
 * Set the Option data (raw access)
 * @function data
 * @tparam string data
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
	meta_bind_func(l, "kind", L_ACCESSOR(byte, TCPOptionLayer, Kind));
	meta_bind_func(l, "data", set_payload<TCPOptionLayer>);
	meta_bind_func(l, "new", l_TCPOption);
	meta_bind_func(l, "new_nop", l_TCP_NOP);
	meta_bind_func(l, "new_eol", l_TCP_EOL);
	meta_bind_func(l, "new_sackp", l_TCP_SACKP);
	meta_bind_func(l, "new_sack", l_TCP_SACK);
	meta_bind_func(l, "new_mss", l_TCP_MSS);
	meta_bind_func(l, "new_wscale", l_TCP_WindowScale);
	meta_bind_func(l, "new_mpjoin", l_TCP_MPTCPJoin);
	meta_bind_func(l, "new_mpcapable", l_TCP_MPTCPCapable);
}
