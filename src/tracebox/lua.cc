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
	Packet *pkt = l_packet_ref::get(l, -1);
	if (!pkt)
		return NULL;

	return pkt;
}

void script_execfile(std::string& filename)
{
	int ret;

	lua_State *l = l_init();
	ShowWarnings = 0;
	ret = luaL_dofile(l, filename.c_str());
	if(ret)
		std::cout << "Lua error: " << luaL_checkstring(l, -1) << std::endl;
}
