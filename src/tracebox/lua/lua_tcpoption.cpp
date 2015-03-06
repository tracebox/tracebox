#include "lua_tcpoption.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_tcpoption_ref::l_TCP_NOP(lua_State *l)
{
	TCPOptionPad *opt = l_tcpoption_ref::new_option_ref<TCPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetKind(1);
	return 1;
}

int l_tcpoption_ref::l_TCP_EOL(lua_State *l)
{
	TCPOptionPad *opt = l_tcpoption_ref::new_option_ref<TCPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetKind(0);
	return 1;
}

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
	meta_bind_func(l, "kind", L_SETTER(byte, TCPOptionLayer, Kind));
	meta_bind_func(l, "data", set_payload<TCPOptionLayer>);
}

void l_tcpoption_ref::register_globals(lua_State *l)
{
	l_layer_ref<TCPOptionLayer>::register_globals(l);
	lua_register(l, "nop", l_TCP_NOP);
	lua_register(l, "eol", l_TCP_EOL);
	lua_register(l, "sackp", l_TCP_SACKP);
	lua_register(l, "sack", l_TCP_SACK);
	lua_register(l, "mss", l_TCP_MSS);
	lua_register(l, "timestamp", l_TCP_Timestamp);
	lua_register(l, "wscale", l_TCP_WindowScale);
	lua_register(l, "mpcapable", l_TCP_MPTCPCapable);
	lua_register(l, "mpjoin", l_TCP_MPTCPJoin);
	l_do(l, "NOP=nop()");
	l_do(l, "EOL=eol()");
	l_do(l, "SACKP=NOP/NOP/sackp()");
	l_do(l, "MSS=mss(1460)");
	l_do(l, "TS=NOP/NOP/timestamp{}");
	l_do(l, "function SACK(blocks) return NOP/NOP/sack(blocks) end");
	l_do(l, "WSCALE=wscale(14)/NOP");
	l_do(l, "MPCAPABLE=mpcapable{}");
	l_do(l, "MPJOIN=mpjoin{}");
}
