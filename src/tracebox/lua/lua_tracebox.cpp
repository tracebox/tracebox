/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */
#include <memory>

#include "lua_packet.hpp"
#include "lua_packetmodifications.h"
#include "lua_arg.h"
#include "../tracebox.h"

/***
 * @module Globals
 * */
/***
 * Contains all arguments that appeared on the command line, in the order they
 * appeared. Spaces in the command line act as separator between arguments,
 * escape them with quotes if you want to pass in a longer string.
 * @tfield vector argv
 * @usage tracebox -l "print(#argv)" Hello " " \" Worl "d
 *
 * 	Will print 4, as there are five arguments:
 * 		1. Hello
 * 		2. " " (without the quotes)
 * 		3. " (an actual quote)
 * 		4. Worl
 * 		5. d (quote was there only to fix hilighting ...)
 * 	Escape-rules depends on your shell.
 */

struct tracebox_info {
	const char *cb;
	lua_State *l;
	std::shared_ptr<const Packet> rcv;
};

/***
 * Callback function type, to be provided as argument to tracebox
 * @function tracebox_callback
 * @see tracebox
 * @tparam num ttl the current TTL value
 * @tparam string r_ip the ip of the router that echoed the probe
 * @tparam PacketModifications mod the packet modifications list
 * @treturn[opt] num 1 to force tracebox to stop sending probes
 * @usage
 * function callback_func(ttl, r_ip, mod)
 * 	print("Sent probe n#" .. tll .. " and received " .. mod:modif():tostring())
 * end
 * */
static int tCallback(void *ctx, uint8_t ttl, std::string& ip,
		PacketModifications *mod)
{
	struct tracebox_info *info = (struct tracebox_info *)ctx;
	int ret;

	info->rcv = mod->modif;

	if (!info->cb)
		return 0;

	lua_pushcfunction(info->l, lua_traceback);
	int err_handler = lua_gettop(info->l);

	lua_getglobal(info->l, info->cb);
	if(lua_type(info->l, -1) != LUA_TFUNCTION) {
		const char* msg = lua_pushfstring(info->l, "`%s' is not a function",
				info->cb);
		luaL_argerror(info->l, -1, msg);
		return -1;
	}

	l_data_type<int>(ttl).push(info->l);

	if (ip == "")
		lua_pushnil(info->l);
	else
		l_data_type<std::string>(ip).push(info->l);

	new l_packetmodifications_ref(mod, info->l);

	int err = lua_pcall(info->l, 3, 1, err_handler);

	if (err) {
		std::cerr << "Error in the callback: " <<
			luaL_checkstring(info->l, -1) << std::endl;
		lua_pop(info->l, 2);
		return -1;
	}
	if (!lua_isnumber(info->l, -1)) {
		lua_pop(info->l, 2);
		return 0;
	}
	ret = lua_tonumber(info->l, -1);
	lua_pop(info->l, 2);
	return ret;
}

/***
 * Start sending the packet with increasing TTL values and compute the
 * differences
 * @function tracebox
 * @tparam Packet pkt the probe packet
 * @tparam[opt] table args see tracebox_args
 * @treturn Packet the echoed packet from the destination or nil
 * @see tracebox_callback
 * @usage tracebox(IP/TCP, { callback = 'callback_func'})
 * */
/***
 * Tracebox optional keyword parameters
 * @table tracebox_args
 * @tfield string callback The callback function to call at each received probe, see tracebox_callback
 * */
int l_Tracebox(lua_State *l)
{
	std::string err;
	int ret = 0;
	std::shared_ptr<Packet> pref = l_packet_ref::get_owner<Packet>(l, 1);
	static struct tracebox_info info = {NULL, l, NULL};
	Packet *pkt = pref.get();
	if (!pkt) {
		std::cerr << "doTracebox: no packet!" << std::endl;
		return 0;
	}
	if (lua_gettop(l) == 1)
		goto no_args;

	v_arg_string_opt(l, 2, "callback", &info.cb);


no_args:
	ret = doTracebox(pref, tCallback, err, &info);
	if (ret < 0) {
		const char* msg = lua_pushfstring(l, "Tracebox error: %s", err.c_str());
		luaL_argerror(l, -1, msg);
		return 0;
	}

	/* Did the server reply ? */
	if (ret == 1 && info.rcv.get())
		new l_packet_ref(new Packet(*info.rcv), l);
	else
		lua_pushnil(l);

	return 1;
}

/***
 * Set a new TTL range for further tracebox calls
 * @function set_ttl_range
 * @tparam table args see set_ttl_range_args
 * @treturn table The old TTL table
 * */
/***
 * Parameters for set_ttl_range
 * @table set_ttl_range_args
 * @tfield num min_ttl The minimal probe TTL
 * @tfield num max_ttl The maximal probe TTL
 * */
int l_set_ttl_range(lua_State *l)
{
	int old_min = get_min_ttl(), old_max = get_max_ttl(), min_ttl, max_ttl,
			new_min, new_max;
	bool min = v_arg_integer_opt(l, 1, "min_ttl", &min_ttl);
	bool max = v_arg_integer_opt(l, 1, "max_ttl", &max_ttl);
	new_min = min ? min_ttl : old_min;
	new_max = max ? max_ttl : old_max;
	if ((min || max) &&	set_tracebox_ttl_range(new_min, new_max))
		return luaL_error(l, "Invalid TTL range: [%d <= %d]", new_min, new_max);
	lua_createtable(l, 0, 2);
	lua_pushstring(l, "min_ttl");
	lua_pushinteger(l, old_min);
	lua_settable(l, -3);
	lua_pushstring(l, "max_ttl");
	lua_pushinteger(l, old_max);
	lua_settable(l, -3);
	return 1;
}
