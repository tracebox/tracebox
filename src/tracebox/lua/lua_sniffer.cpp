#include "lua_sniffer.h"
#include "lua_packet.hpp"

static int l_sniffer_cb(Crafter::Packet *p, void *ctx)
{
	l_sniffer_ref *s = static_cast<l_sniffer_ref*>(ctx);
	lua_getglobal(s->ctx, s->cb.c_str());
	if(lua_type(s->ctx, -1) != LUA_TFUNCTION) {
		lua_pushfstring(s->ctx, "`%s' is not a function", s->cb.c_str());
		return -1;
	}
	new l_packet_ref(p, s->ctx);
	int err = lua_pcall(s->ctx, 1, 1, 0);
	if (err) {
		std::cerr << "Error in the callback: " << luaL_checkstring(s->ctx, -1) << std::endl;
		lua_pop(s->ctx, 1);
		return -1;
	}
	if (!lua_isnumber(s->ctx, -1)) {
		lua_pop(s->ctx, 1);
		return 0;
	}
	int ret = lua_tonumber(s->ctx, -1);
	lua_pop(s->ctx, 1);
	return ret;
}

/***
 * An object that will intercept packets
 * @classmod TbxSniffer
 */
/***
 * Constructs a new TbxSniffer
 * @function new
 * @tparam table key a list of arguments that will be passed to iptables
 * @tparam string cb the name of a callback function, see @{sniffer_callback}
 * @usage TbxSniffer.new({'-p', 'tcp', '--dport', '80'}, callback_func)
 * @treturn TbxSniffer
 */
int l_sniffer_ref::l_Sniffer(lua_State *l)
{
	luaL_checktype(l, 1, LUA_TTABLE);
	std::vector<const char*> key;
	for (int i = 1; ; ++i, lua_pop(l, 1)) {
		lua_rawgeti(l, 1, i);
		if (lua_isnil(l, -1)) {
			lua_pop(l, 1);
			break;
		}
		const char* arg = luaL_checkstring(l, -1);
		key.push_back(arg);
	}
	const char *cb = luaL_checkstring(l, 2);
	TbxSniffer *s = new TbxSniffer(key, l_sniffer_cb);
	l_sniffer_ref *ref = new l_sniffer_ref(s, l);
	ref->cb = cb;
	return 1;
}
/***
 * The callback function for the sniffer
 * @function sniffer_callback
 * @tparam Packet pkt the received packet
 * @treturn num x -1 in case of error, 0 if the packet was consumed, 1 otherwise
 */

/***
 * Start sniffing and calls the callback function for each new packet.
 * Will never return unless @{stop} is called from another thread
 * @function start
 */
int l_sniffer_ref::l_start(lua_State *l)
{
	l_sniffer_ref *s = dynamic_cast<l_sniffer_ref *>(l_sniffer_ref::get_instance(l, 1));
	s->ctx = l;
	s->val->start(s);
	return 0;
}

/***
 * Stop sniffing
 * @function stop
 */
int l_sniffer_ref::l_stop(lua_State *l)
{
	TbxSniffer *s = l_sniffer_ref::get(l, 1);
	s->stop();
	return 0;
}

void l_sniffer_ref::register_members(lua_State *l)
{
	l_ref<TbxSniffer>::register_members(l);
	meta_bind_func(l, "new", l_Sniffer);
	meta_bind_func(l, "start", l_start);
	meta_bind_func(l, "stop", l_stop);
}
