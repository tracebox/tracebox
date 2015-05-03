#include "lua_tcptfo.h"
#include "lua_arg.h"

using namespace Crafter;

#define COOKIE_MAXLEN 16
static size_t _read_cookie(byte **storage, lua_State *l, int n)
{
	static byte cookie[COOKIE_MAXLEN];
	int i;
	memset(cookie, 0, sizeof(cookie));
	luaL_checktype(l, n, LUA_TTABLE);
	for (i = 1; i <= COOKIE_MAXLEN; ++i, lua_pop(l, 1)) {
		lua_rawgeti(l, n, i);
		if (lua_isnil(l, -1)) {
			lua_pop(l, 1);
			break;
		}
		cookie[i-1] = lua_tointeger(l, -1);
	}
	*storage = cookie;
	return i-1;
}

static void _write_cookie(lua_State *l, TCPOptionFastOpen *tfo)
{
	byte cookie[COOKIE_MAXLEN];
	lua_newtable(l);
	tfo->GetCookie(cookie);
	for (size_t i = 0; i < tfo->CookieLen() && i < sizeof(cookie); ++i) {
		l_data_type<int>(cookie[i]).push(l);
		lua_rawseti(l, -2, i + 1);
	}
}

/***
 * The TCP Fast Open option
 * @classmod TCPTFO
 */
/***
 * Create a new TFO Option
 * @function new
 * @tparam[opt] table cookie the bytes of the cookie
 * @treturn TCPTFO
 */
int l_tcptfo_ref::l_TCP_TFO(lua_State *l)
{
	TCPOptionFastOpen *opt;

	opt = l_tcptfo_ref::new_ref(l);
	if (!opt)
		return 0;

	byte *cookie;
	size_t len = _read_cookie(&cookie, l, 1);
	if (len)
		opt->setCookie(cookie, len);

	return 1;
}

int _access_cookie(lua_State *l)
{
	TCPOptionFastOpen *o = l_tcptfo_ref::get(l, 1);
	if (lua_gettop(l) == 1)
		_write_cookie(l, o);
	else {
		byte *cookie;
		size_t len = _read_cookie(&cookie, l, 1);
		if (len)
			o->setCookie(cookie, len);
	}
	return 1;
}

/***
 * The TCP TFO Option
 * @type TCPTFO
 */
void l_tcptfo_ref::register_members(lua_State *l)
{
	l_layer_ref<TCPOptionFastOpen>::register_members(l);
	/***
	 * Get/Set the tfo cookie
	 * @function cookie
	 * @tparam[opt] table cookie Set the cookie value
	 * @treturn table cookie
	 */
	meta_bind_func(l, "cookie", _access_cookie);
}
