#include "lua_global.h"

#include <ctime>
#include <cstring>

/***
 * @module Globals
 */

static void print_object(lua_State *L, int i)
{
	int t = lua_type(L, i);
	std::cerr << lua_typename(L, t) << ": ";
	switch (t) {
		case LUA_TSTRING:  /* strings */
			std::cerr << lua_tostring(L, i);
			break;

		case LUA_TBOOLEAN:  /* booleans */
			std::cerr << (lua_toboolean(L, i) ? "true" : "false");
			break;

		case LUA_TNUMBER:  /* numbers */
			std::cerr << lua_tonumber(L, i);
			break;

		case LUA_TUSERDATA:
			dynamic_cast<_ref_base*>((*(_ref_base**)
						(lua_touserdata(L, i))))->debug(std::cerr);
			break;

		default:  /* other values */
			break;
	}
}

void stackDump (lua_State *L, const char* f, size_t l) {
	std::cerr << "Globals:" << std::endl;
	lua_pushglobaltable(L);
	lua_pushnil(L);
	while (lua_next(L,-2) != 0) {
		if (lua_isstring(L, -2))
			std::cerr << "[" << luaL_checkstring(L, -2) << "] ";
		print_object(L, -1);
		lua_pop(L, 1);
		std::cerr << " / ";
	}
	lua_pop(L,1);
	std::cerr << "------------" << std::endl;

	int i;
	int top = lua_gettop(L);
	std::cerr << "Stack content (at " << f << "/" << l << "):" << std::endl;
	for (i = 1; i <= top; i++) {
		std::cerr << "[" << i << "] ";
		print_object(L, i);
		std::cerr << std::endl;
	}
	lua_pop(L, i);
	std::cerr << "===========" << std::endl;
}

/***
 * Suspend the current execution thread for a fixed amount of time
 * @function sleep
 * @tparam num the number of milliseconds during which the thread should sleep
 */
int l_sleep(lua_State *l)
{
	long ms = luaL_checkinteger(l, 1);
	struct timespec tp;
	tp.tv_nsec = 1000 * (ms % 1000);
	tp.tv_sec = ms / 1000;

	if (nanosleep(&tp, NULL))
		std::perror("sleep() failed");

	return 0;
}
