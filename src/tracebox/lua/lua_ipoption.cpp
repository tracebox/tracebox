#include "lua_ipoption.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_ipoption_ref::l_IP_NOP(lua_State *l)
{
	IPOptionPad *opt = l_ipoption_ref::new_option_ref<IPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetOption(1);
	return 1;
}

int l_ipoption_ref::l_IP_EOL(lua_State *l)
{
	IPOptionPad *opt = l_ipoption_ref::new_option_ref<IPOptionPad>(l);
	if (opt == NULL)
		return 0;
	opt->SetOption(0);
	return 1;
}

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

void l_ipoption_ref::register_globals(lua_State *l)
{
	l_layer_ref<IPOption>::register_globals(l);
	lua_register(l, "ip_nop", l_IP_NOP);
	lua_register(l, "ip_eol", l_IP_EOL);
	lua_register(l, "rr", l_IP_RR);
	lua_register(l, "ssrr", l_IP_SSRR);
	lua_register(l, "lsrr", l_IP_LSRR);
	lua_register(l, "traceroute", l_IP_Traceroute);
	l_do(l, "IP_NOP=ip_nop()");
	l_do(l, "IP_EOL=ip_eol()");
	l_do(l, "function RR(n) return rr(n)/IP_NOP end");
	l_do(l, "function SSRR(addrs) return ssrr(addrs)/IP_NOP end");
	l_do(l, "function LSRR(addrs) return lsrr(addrs)/IP_NOP end");
}
