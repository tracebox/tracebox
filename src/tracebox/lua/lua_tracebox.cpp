/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

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
	l_packet_ref *probe;
	const char *cb;
	lua_State *l;
	Packet *rcv;
};

/***
 * Callback function type, to be provided as argument to tracebox
 * @function tracebox_callback
 * @see tracebox
 * @tparam num ttl the current TTL value
 * @tparam string r_ip the ip of the router that echoed the probe
 * @tparam Packet probe the probe packet
 * @tparam Packet rcv the echoed packet
 * @tparam PacketModifications mod the packet modifications list
 * @treturn[opt] num 1 to force tracebox to stop sending probes
 * @usage
 * function callback_func(ttl, r_ip, probe, rcv, mod)
 * 	print("Sent probe n#" .. tll)
 * end
 * */
static int tCallback(void *ctx, int ttl, std::string& ip,
	const Packet * const probe, Packet *rcv, PacketModifications *mod)
{
	(void)probe;
	struct tracebox_info *info = (struct tracebox_info *)ctx;
	int ret;

	info->rcv = rcv;

	if (!info->cb)
		return 0;

	lua_pushcfunction(info->l, lua_traceback);
	int err_handler = lua_gettop(info->l);

	lua_getglobal(info->l, info->cb);
	if(lua_type(info->l, -1) != LUA_TFUNCTION) {
		const char* msg = lua_pushfstring(info->l, "`%s' is not a function", info->cb);
		luaL_argerror(info->l, -1, msg);
		return -1;
	}

	l_data_type<int>(ttl).push(info->l);

	if (ip == "")
		lua_pushnil(info->l);
	else
		l_data_type<std::string>(ip).push(info->l);

	info->probe->push(info->l);

	l_packet_ref *rcv_ref = NULL;
	if (!rcv)
		lua_pushnil(info->l);
	else
		rcv_ref = new l_packet_ref((Packet *)rcv, info->l);


	if (!mod)
		lua_pushnil(info->l);
	else if (rcv_ref)
		new l_packetmodifications_ref(rcv_ref, mod, info->l);
	 else
		new l_packetmodifications_ref(mod, info->l);

	int err = lua_pcall(info->l, 5, 1, err_handler);

	if (err) {
		std::cerr << "Error in the callback: " << luaL_checkstring(info->l, -1) << std::endl;
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
 * @tparam[opt] table args a table with the name of a callback function at key 'callback'
 * @treturn Packet the echoed packet from the destination or nil
 * @see tracebox_callback
 * @usage tracebox(IP/TCP, { callback = 'callback_func'})
 * */
int l_Tracebox(lua_State *l)
{
	std::string err;
	int ret = 0;
	l_packet_ref *pref = static_cast<l_packet_ref*>(l_packet_ref::get_instance(l, 1));
	static struct tracebox_info info = {pref, NULL, l, NULL};
	Packet *pkt = pref->val;
	if (!pkt) {
		std::cerr << "doTracebox: no packet!" << std::endl;
		return 0;
	}
	if (lua_gettop(l) == 1)
		goto no_args;

	v_arg_string_opt(l, 2, "callback", &info.cb);

no_args:
	ret = doTracebox(pkt, tCallback, err, &info);
	if (ret < 0) {
		const char* msg = lua_pushfstring(l, "Tracebox error: %s", err.c_str());
		luaL_argerror(l, -1, msg);
		return 0;
	}

	/* Did the server reply ? */
	if (ret == 1 && info.rcv)
		new l_packet_ref((Packet *)info.rcv, l);
	else
		lua_pushnil(l);

	return 1;
}
