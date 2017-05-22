/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_raw.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

static void _fill_byte_vec(std::vector<byte> &vec, lua_State *l, int idx)
{
	luaL_checktype(l, idx, LUA_TTABLE);
	for (int i = 1;; ++i, lua_pop(l, 1)) {
		lua_rawgeti(l, -1, i);
		if (lua_isnil(l, -1)) {
			lua_pop(l, 1);
			break;
		}
		vec.push_back(lua_tointeger(l, -1));
	}
}

static void _get_byte_string(const char **dest, size_t *size,
		lua_State *l, int idx)
{
	*dest = luaL_checklstring(l, idx, size);
}

/***
 * The Raw Layer, inherits from @{Base_Object}
 * @classmod Raw
 */
/***
 * Constructor for a Raw Layer
 * @function new
 * @tparam[opt] string data the data for this layer.
 * @tparam[opt] table bytes the data for this layer, as byte values.
 * @treturn Raw a new Raw object
 * @usage Raw.new('Hello World!')
 * */
int l_raw_ref::l_Raw(lua_State *l)
{
	RawLayer *raw;
	char const *payload = NULL;
	size_t payload_len = 0;
	std::vector<byte> bytes;

	if (lua_istable(l, 1)) {
		_fill_byte_vec(bytes, l, 1);
	} else {
		_get_byte_string(&payload, &payload_len, l, 1);
	}

	raw = l_raw_ref::new_ref(l);
	if (!raw)
		return 0;

	if (payload)
		raw->SetPayload((byte *)payload, payload_len);
	if (bytes.size())
		raw->SetPayload(&bytes[0], bytes.size());

	return 1;
}

/***
 * Get/Set the payload data for this layer
 * @function data
 * @tparam[opt] string data
 * @treturn string data
 * */
int l_raw_ref::l_data(lua_State *l)
{
	char const *payload = NULL;
	size_t payload_len = 0;

	RawLayer *o = l_raw_ref::extract(l, 1);
	if (lua_gettop(l) > 1) {
		_get_byte_string(&payload, &payload_len, l, 2);
		o->SetPayload((byte *)payload, payload_len);
	} else
		l_data_type<std::string>(o->GetStringPayload()).push(l);
	return 1;
}

/***
 * Get/Set the payload bytes for this layer
 * @function bytes
 * @tparam[opt] table bytes a list of bytes
 * @treturn table bytes
 */
int l_raw_ref::l_bytes(lua_State *l)
{
	RawLayer *o = l_raw_ref::extract(l, 1);
	if (lua_gettop(l) == 1) {
		lua_newtable(l);
		const byte *bytes = o->GetPayload().GetRawPointer();
		for (size_t i = 0; i < o->GetPayloadSize(); ++i) {
			l_data_type<int>(*bytes).push(l);
			lua_rawseti(l, -2, i + 1);
			++bytes;
		}
	} else {
		std::vector<byte> bytes;
		_fill_byte_vec(bytes, l, 2);
		o->SetPayload(&bytes[0], bytes.size());
	}
	return 1;
}

void l_raw_ref::register_members(lua_State *l)
{
	l_layer_ref<RawLayer>::register_members(l);
	meta_bind_func(l, "new", l_Raw);
	meta_bind_func(l, "data", l_data);
	meta_bind_func(l, "bytes", l_bytes);
}
