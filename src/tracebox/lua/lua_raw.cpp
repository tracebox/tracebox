#include "lua_raw.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

int l_raw_ref::l_Raw(lua_State *l)
{
	RawLayer *raw;
	const char *payload = luaL_checkstring(l, 1);

	raw = l_raw_ref::new_ref(l);
	if (!raw)
		return 0;

	raw->SetPayload(payload);
	return 1;
}

void l_raw_ref::register_members(lua_State *l)
{
	l_layer_ref<RawLayer>::register_members(l);
	meta_bind_func(l, "data", set_payload<RawLayer>);
}

void l_raw_ref::register_globals(lua_State *l)
{
	l_layer_ref<RawLayer>::register_globals(l);
	lua_register(l, "raw", l_Raw);
}
