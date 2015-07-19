#include "lua_tcpedo.h"
#include "lua_arg.h"

using namespace Crafter;

/***
 * The TCP Edo option
 * @classmod TCPEDO
 */
/***
 * The TCP EDO Option
 * @type TCPEDO
 */
void l_tcpedoopt_ref::register_members(lua_State *l)
{
	l_layer_ref<TCPOptionEDO>::register_members(l);
	/***
	 * Get/Set the Length field in the edo option
	 * @function length
	 * @tparam[opt] num length
	 * @treturn num length
	 */
	meta_bind_func(l, "length",
			L_ACCESSOR_BASE(byte, TCPOptionEDO, TCPOption, Length));

	/***
	 * Get the Header Length field in the edo option
	 * @function headerlength
	 * @treturn num length The 'real' number of internet words of the TCP header
	 */
	meta_bind_func(l, "headerlength",
			L_GETTER(short_word, TCPOptionEDO, HeaderLength));
	/***
	 * Get the Segment Length field in the edo option
	 * @function segmentlength
	 * @treturn num length number of bytes in the TCP segment
	 */
	meta_bind_func(l, "segmentlength",
			L_GETTER(short_word, TCPOptionEDO, SegmentLength));

#define META_FLAG(f) metatable_bind(l, #f, l_data_type<byte>(TCPOptionEDO::f))
	/***
	 * The edo request, 2 bytes long, to be used in the SYN(+ACK) negociation
	 * @tfield num EDOREQUEST
	 */
	META_FLAG(EDOREQUEST);
	/***
	 * The edo option, 4 bytes long, containing the header length field
	 * @tfield num EDO
	 */
	META_FLAG(EDO);
	/***
	 * The edo option, 6 bytes long, containing the header length and segment length fields
	 * @tfield num EDOEXT
	 */
	META_FLAG(EDOEXT);
#undef META_FLAG
}
/***
 * Create a new EDO Option
 * @function new
 * @tparam[opt] num length the size of the EDO option, use one of the constants
 * defined as field in this class: @{EDOREQUEST}, @{EDO}, @{EDOEXT}
 * @treturn TCPEDO
 */
int l_tcpedoopt_ref::l_TCP_EDO(lua_State *l)
{
	TCPOptionEDO *opt = l_tcpedoopt_ref::new_ref(l);
	if (!opt)
		return 0;
	if (lua_gettop(l)) {
		opt->SetLength(luaL_checkinteger(l, 1));
	}
	return 1;
}
