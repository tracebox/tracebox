/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */


#include "lua/lua_packet.hpp"
#include "config.h"

extern lua_State* l_init();

using namespace Crafter;

Packet *script_packet(std::string& cmd)
{
	int ret;
	std::string command = "pkt=" + cmd;

	lua_State *l = l_init();
	ret = luaL_dostring(l, command.c_str());
	if(ret) {
		std::cout << "Lua error: " << luaL_checkstring(l, -1) << std::endl;
		return NULL;
	}

	lua_getglobal(l, "pkt");
	/* As we'll clean the lua state, copy the produced packet */
	Packet *pkt = new Packet(*l_packet_ref::get(l, -1));
	if (!pkt)
		return NULL;

	lua_close(l);
	return pkt;
}

static void _add_argv(lua_State *l, int argc, char **argv)
{
	lua_newtable(l);
	for (int i = 0; i < argc; ++i) {
		lua_pushstring(l, argv[i]);
		lua_rawseti(l, -2, i+1);
	}
	lua_setglobal(l, "argv");
}

int script_exec(const char *script, int argc, char **argv)
{
	int ret;

	lua_State *l = l_init();
	_add_argv(l, argc, argv);
	ret = luaL_dostring(l, script);
	if (ret)
		std::cout << "Lua error: " << luaL_checkstring(l, -1) << std::endl;

	lua_close(l);
	return ret;
}

int script_execfile(const char *filename, int argc, char **argv)
{
	int ret;

	lua_State *l = l_init();
	_add_argv(l, argc, argv);
	lua_pushcfunction(l, lua_traceback);
	int err_handler = lua_gettop(l);
	if ((ret = luaL_loadfile(l, filename)))
		perror("script_execfile");
	else
		if ((ret = lua_pcall(l, 0, LUA_MULTRET, err_handler))) {
			std::cerr << "Lua error: " << luaL_checkstring(l, -1) << std::endl;
		} else {
			ret = lua_tointeger(l, -1);
		}
	lua_close(l);
	return ret;
}
