/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_base.hpp"

/***
 * Abstract type for all custom classes exposed from cpp,
 * exposed to lua with reference couting.
 * @classmod __cpp_obj
 */
/***
 * Garbage-collect this object -- DO NOT CALL.
 * Will be called by the Lua interpreter in a GC run.
 * @function __gc
 */
/***
 * Get this object reference count.
 * @function __cpp_ref_count
 * @treturn num refcount
 */
/***
 * Get the reference count of the owner of this object
 * @function __cpp_ownerref_count
 * @treturn num refcount the reference count, or nil if this object is self-owned
 */
/***
 * The cpp classname associated held by this object. This is an opaque value.
 * @tfield string __tbx_classname
 */
const char *l_classname_field = "__tbx_classname";
size_t _ref_base::instance_count = 0;

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
void l_data_type<int32_t>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
int32_t l_data_type<int32_t>::get(lua_State *l, int n) { return luaL_checkinteger(l, n); }

template<>
void l_data_type<unsigned long>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
unsigned long l_data_type<unsigned long>::get(lua_State *l, int n) { return luaL_checkinteger(l, n); }

template<>
void l_data_type<uint32_t>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
uint32_t l_data_type<uint32_t>::get(lua_State *l, int n) { return luaL_checkinteger(l, n); }

template<>
void l_data_type<uint16_t>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
uint16_t l_data_type<uint16_t>::get(lua_State *l, int n) { return luaL_checkinteger(l, n); }

template<>
void l_data_type<uint8_t>::push(lua_State *l) { lua_pushinteger(l, val); }
template<>
uint8_t l_data_type<uint8_t>::get(lua_State *l, int n) { return luaL_checkinteger(l, n); }

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

int lua_traceback(lua_State *L) {
    lua_getglobal(L, "debug");
    lua_getfield(L, -1, "traceback");
    lua_pushvalue(L, 1);
    lua_pushinteger(L, 2);
    lua_call(L, 2, 1);
    return 1;
}
