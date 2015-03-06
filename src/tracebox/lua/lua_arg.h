#ifndef __LUA_ARG_H_
#define __LUA_ARG_H_

#include "lua_base.hpp"

int v_arg(lua_State* L, int argt, const char* field);

const char* v_arg_lstring(lua_State* L, int argt, const char* field, size_t* size, const char* def);

void v_arg_lstring_(lua_State* L, int argt, const char *field, const char **val);

const char* v_arg_string(lua_State* L, int argt, const char* field);

bool v_arg_string_opt(lua_State* L, int argt, const char* field, const char **val);

lua_Integer v_arg_integer_get_(lua_State* L, int argt, const char* field);

int v_arg_integer(lua_State* L, int argt, const char* field);

bool v_arg_integer_opt(lua_State* L, int argt, const char* field, int *val);

bool v_arg_integer64_opt(lua_State* L, int argt, const char* field, uint64_t *val);

bool v_arg_boolean_get_(lua_State* L, int argt, const char* field);

bool v_arg_boolean_opt(lua_State* L, int argt, const char* field, bool *val);

#endif
