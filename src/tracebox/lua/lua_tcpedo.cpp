#include "lua_tcpedo.h"
#include "lua_arg.h"

using namespace Crafter;

/***
 * The TCP Edo option
 * @module TCPExtendedDataOption
 */
/***
 * The TCP EDO Option
 * @type TCPEDO
 */
void l_tcpedoopt_ref::register_members(lua_State *l)
{
	l_layer_ref<TCPEDO>::register_members(l);
	/***
	 * Get/Set the Length field in the edo
	 * @function length
	 * @tparam[opt] num length Set the length value
	 * @treturn num length
	 */
	meta_bind_func(l, "length", L_ACCESSOR(byte, TCPEDO, Length));
}
/***
 * Create a new EDO Option
 * @function new
 * @treturn TCPEDO
 */
int l_tcpedoopt_ref::l_TCP_EDO(lua_State *l)
{
	TCPEDO *opt;

	opt = l_tcpedoopt_ref::new_ref(l);
	if (!opt)
		return 0;
	return 1;
}

/***
 * The TCP EDORequest Option
 * @type TCPEDORequest
 */
void l_tcpedoropt_ref::register_members(lua_State *l)
{
	l_layer_ref<TCPEDORequest>::register_members(l);
	/***
	 * Get/Set the Length field in the edo
	 * @function length
	 * @tparam[opt] num length Set the length value
	 * @treturn num length
	 */
	meta_bind_func(l, "length", L_ACCESSOR(byte, TCPEDORequest, Length));
}

/***
 * Create a new EDORequest Option
 * @function new
 * @treturn TCPEDORequest
 */
int l_tcpedoropt_ref::l_TCP_EDOR(lua_State *l)
{
	TCPEDORequest *opt;
	opt = l_tcpedoropt_ref::new_ref(l);
	if (!opt)
		return 0;
	return 1;
}
