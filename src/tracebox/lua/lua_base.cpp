#include "lua_base.hpp"

/***
 * The basic methods supported by most objects
 * @classmod Base_Object
 */
/***
 * Return the textual representation of the object.
 * @function print
 * @see tostring
 * @treturn string
 */
/***
 * Return the Hexdacimal representation of the object.
 * @function hexdump
 * @treturn string
 */
/***
 * Concatenate two objects into a Packet
 * @function __concat
 * @usage pkt = IP / TCP / raw("Hello World!")
 * @treturn Packet
 */
/***
 * Same than @{__concat}
 * @function __add
 * @see __concat
 */
/***
 * Same than @{__concat}
 * @function __div
 * @see __concat
 */
/***
 * Same than @{print}
 * @function __tostring
 * @see print
 */

void stackDump (lua_State *L, const char* f, size_t l) {
	int i;
	int top = lua_gettop(L);
	std::cerr << "Stack content (at " << f << "/" << l << "):" << std::endl;
	for (i = 1; i <= top; i++) {/* repeat for each level */
		int t = lua_type(L, i);
		std::cerr << "[" << i << "] " << lua_typename(L, t) << ": ";
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
				(*static_cast<l_ref<Crafter::Layer>**>(lua_touserdata(L, i)))->debug(std::cerr);

			default:  /* other values */
				break;
		}
		std::cerr << std::endl;
	}
}

void l_do(lua_State *l, const char *m)
{
	int r = luaL_dostring(l, m);
	if (r) {
		std::cerr << "Lua error for " << m << " :\n"
			<< luaL_checkstring(l, -1) << std::endl;
		L_DUMP_STACK(l);
	}
}

void meta_bind_func(lua_State *l, const char *key, lua_CFunction f)
{
	metatable_bind(l, key, l_data_type<lua_CFunction>(f));
}

template<>
void l_data_type<lua_Number>::push(lua_State *l) { lua_pushnumber(l, val); }
template<>
lua_Number l_data_type<lua_Number>::get(lua_State *l, int n) { return luaL_checknumber(l, n); }

template<>
void l_data_type<int>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
int l_data_type<int>::get(lua_State *l, int n) { return luaL_checkint(l, n); }

template<>
void l_data_type<Crafter::word>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
Crafter::word l_data_type<Crafter::word>::get(lua_State *l, int n) { return luaL_checkint(l, n); }

template<>
void l_data_type<Crafter::short_word>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
Crafter::short_word l_data_type<Crafter::short_word>::get(lua_State *l, int n) { return luaL_checkint(l, n); }

template<>
void l_data_type<Crafter::byte>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
Crafter::byte l_data_type<Crafter::byte>::get(lua_State *l, int n) { return luaL_checkint(l, n); }

template<>
void l_data_type<const char*>::push(lua_State *l) { lua_pushstring(l, val); }
template<>
const char* l_data_type<const char*>::get(lua_State *l, int n) { return luaL_checkstring(l, n); }

template<>
void l_data_type<std::string>::push(lua_State *l) { lua_pushstring(l, val.c_str()); }
template<>
std::string l_data_type<std::string>::get(lua_State *l, int n) { return luaL_checkstring(l, n); }

template<>
void l_data_type<lua_CFunction>::push(lua_State *l) { lua_pushcfunction(l, val); }
template<>
lua_CFunction l_data_type<lua_CFunction>::get(lua_State *l, int n)
{
	luaL_checktype(l, n, LUA_TFUNCTION);
	return lua_tocfunction(l, n);
}


