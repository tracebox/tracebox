#include "lua_raw.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/***
 * The Raw Layer, inherits from @{Base_Object}
 * @classmod Raw
 */
/***
 * Constructor for a Raw Layer
 * @function new
 * @tparam string data the data for this layer
 * @treturn Raw a new Raw object
 * @usage Raw.new('Hello World!')
 * */
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
	meta_bind_func(l, "new", l_Raw);
	/***
	 * Set the payload data for this layer
	 * @function data
	 * @tparam string data
	 * */
	meta_bind_func(l, "data", set_payload<RawLayer>);
}
