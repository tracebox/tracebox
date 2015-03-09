#include "lua_ipoption.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * Options for the IP Layer, inherits from @{Base_Object}
 * @classmod IPOption
 */
/***
 * Create a new NOP Option (Option=1)
 * @function new_nop
 * @treturn IPOption
 */
int l_ipoption_ref::l_IP_NOP(lua_State *l)
{
	IPOptionPad *opt = l_ipoption_ref::new_option_ref<IPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetOption(1);
	return 1;
}

/***
 * Create a new EOL Option (Option=0)
 * @function new_eol
 * @treturn IPOption
 */
int l_ipoption_ref::l_IP_EOL(lua_State *l)
{
	IPOptionPad *opt = l_ipoption_ref::new_option_ref<IPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetOption(0);
	return 1;
}

/***
 * Create a new SSRR Option
 * @function new_ssrr
 * @tparam table ips a list of IPs
 * @treturn IPOption
 * @usage IPOption.new{'1.1.1.1', '2.2.2.2', '3.3.3.3'}
 */
int l_ipoption_ref::l_IP_SSRR(lua_State *l)
{
	IPOptionSSRR *opt;
	std::vector<std::string> ips;

	if (!lua_istable(l, 1)) {
		const char* msg = lua_pushfstring(l, "argument must be a table");
		luaL_argerror(l, 1, msg);
		return 0;
	}

	lua_pushnil(l);
	while (lua_next(l, 1)) {
		const char *ip = luaL_checkstring(l, -1);
		ips.push_back(ip);
		lua_pop(l, 1);
	}

	opt = l_ipoption_ref::new_option_ref<IPOptionSSRR>(l);
	if (!opt)
		return 0;

	opt->SetPointer(4);
	/* Put the raw IPs data in the optoin payload */
	opt->SetPayload(IPtoRawData(ips));

	return 1;
}

/***
 * Create a new LSRR Option
 * @function new_lsrr
 * @tparam table ips a list of IPs
 * @treturn IPOption
 */
int l_ipoption_ref::l_IP_LSRR(lua_State *l)
{
	IPOptionLSRR *opt;
	std::vector<std::string> ips;

	if (!lua_istable(l, 1)) {
		const char* msg = lua_pushfstring(l, "argument must be a table");
		luaL_argerror(l, 1, msg);
		return 0;
	}

	lua_pushnil(l);
	while (lua_next(l, 1)) {
		const char *ip = luaL_checkstring(l, -1);
		ips.push_back(ip);
		lua_pop(l, 1);
	}

	opt = l_ipoption_ref::new_option_ref<IPOptionLSRR>(l);
	if (!opt)
		return 0;

	opt->SetPointer(4);
	/* Put the raw IPs data in the optoin payload */
	opt->SetPayload(IPtoRawData(ips));

	return 1;
}

/***
 * Create a new RR Option
 * @function new_rr
 * @tparam number n the number of NULL(0.0.0.0) addresses to put in the RR
 * @treturn IPOption
 */
int l_ipoption_ref::l_IP_RR(lua_State *l)
{
	IPOptionRR *opt;
	int n = luaL_checknumber(l, 1);
	std::vector<std::string> ips(n, "0.0.0.0");

	opt = l_ipoption_ref::new_option_ref<IPOptionRR>(l);
	if (!opt)
		return 0;

	opt->SetPointer(4);
	/* Put the raw IPs data in the optoin payload */
	opt->SetPayload(IPtoRawData(ips));

	return 1;
}

/***
 * Create a new Traceroute Option
 * @function new_traceroute
 * @tparam string orig_ip the original IP
 * @treturn IPOption
 */
int l_ipoption_ref::l_IP_Traceroute(lua_State *l)
{
	IPOptionTraceroute *opt;
	const char *src = luaL_checkstring(l, 1);

	opt = l_ipoption_ref::new_option_ref<IPOptionTraceroute>(l);
	if (!opt)
		return 0;

	opt->SetIDNumber(rand() % USHRT_MAX);
	opt->SetOrigIP(src);

	return 1;
}

void l_ipoption_ref::register_members(lua_State *l)
{
	l_layer_ref<IPOptionLayer>::register_members(l);
	meta_bind_func(l, "new_nop", l_IP_NOP);
	meta_bind_func(l, "new_eol", l_IP_EOL);
	meta_bind_func(l, "new_ssrr", l_IP_SSRR);
	meta_bind_func(l, "new_lsrr", l_IP_LSRR);
	meta_bind_func(l, "new_rr", l_IP_RR);
	meta_bind_func(l, "new_traceroute", l_IP_Traceroute);
}
