/*
 *  Copyright (C) 2013  Gregory Detal <gregory.detal@uclouvain.be>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

#include "lua/lua_global.h"


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
		lua_rawseti(l, -2, i);
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
	ret = luaL_dofile(l, filename);
	if(ret)
		std::cout << "Lua error: " << luaL_checkstring(l, -1) << std::endl;

	lua_close(l);
	return ret;
}
