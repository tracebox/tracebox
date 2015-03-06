#include "lua_arg.h"

int v_arg(lua_State* L, int argt, const char* field)
{
	luaL_checktype(L, argt, LUA_TTABLE);

	lua_getfield(L, argt, field);

	if(lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return 0;
	}
	return lua_gettop(L);
}

const char* v_arg_lstring(lua_State* L, int argt, const char* field, size_t* size, const char* def)
{
	if(!v_arg(L, argt, field))
	{
		if(def) {
			lua_pushstring(L, def);
			return lua_tolstring(L, -1, size);
		} else {
			const char* msg = lua_pushfstring(L, "%s is missing", field);
			luaL_argerror(L, argt, msg);
		}
	}

	if(!lua_tostring(L, -1)) {
		const char* msg = lua_pushfstring(L, "%s is not a string", field);
		luaL_argerror(L, argt, msg);
	}

	return lua_tolstring(L, -1, size);
}

void v_arg_lstring_(lua_State* L, int argt, const char *field, const char **val)
{
	if(!lua_tostring(L, -1)) {
		const char* msg = lua_pushfstring(L, "%s is not a string", field);
		luaL_argerror(L, argt, msg);
	}

	*val = lua_tolstring(L, -1, NULL);
}

const char* v_arg_string(lua_State* L, int argt, const char* field)
{
	return v_arg_lstring(L, argt, field, NULL, NULL);
}

bool v_arg_string_opt(lua_State* L, int argt, const char* field, const char **val)
{
	if(!v_arg(L, argt, field))
		return false;
	v_arg_lstring_(L, argt, field, val);
	return true;
}

lua_Integer v_arg_integer_get_(lua_State* L, int argt, const char* field)
{
	if(lua_type(L, -1) != LUA_TNUMBER) {
		const char* msg = lua_pushfstring(L, "%s is not an integer", field);
		luaL_argerror(L, argt, msg);
	}

	return lua_tointeger(L, -1);
}

int v_arg_integer(lua_State* L, int argt, const char* field)
{
	if(!v_arg(L, argt, field))
	{
		const char* msg = lua_pushfstring(L, "%s is missing", field);
		luaL_argerror(L, argt, msg);
	}

	return (int)v_arg_integer_get_(L, argt, field);
}

bool v_arg_integer_opt(lua_State* L, int argt, const char* field, int *val)
{
	if(!v_arg(L, argt, field))
		return false;

	*val = (int)v_arg_integer_get_(L, argt, field);
	return true;
}

bool v_arg_integer64_opt(lua_State* L, int argt, const char* field, uint64_t *val)
{
	if(!v_arg(L, argt, field))
		return false;

	*val = (uint64_t)v_arg_integer_get_(L, argt, field);
	return true;
}

bool v_arg_boolean_get_(lua_State* L, int argt, const char* field)
{
	if(lua_type(L, -1) != LUA_TBOOLEAN) {
		const char* msg = lua_pushfstring(L, "%s is not an boolean", field);
		luaL_argerror(L, argt, msg);
	}

	return lua_toboolean(L, -1);
}

bool v_arg_boolean_opt(lua_State* L, int argt, const char* field, bool *val)
{
	if(!v_arg(L, argt, field))
		return false;

	*val = v_arg_boolean_get_(L, argt, field);
	return true;
}
