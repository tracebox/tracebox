#include "lua_sniffer.h"
#include "lua_packet.hpp"
#include "../tracebox.h"

static int l_sniffer_cb(Crafter::Packet *p, void *ctx)
{
	l_sniffer_ref *s = static_cast<l_sniffer_ref*>(ctx);
	lua_pushcfunction(s->ctx, lua_traceback);
	int err_handler = lua_gettop(s->ctx);
	lua_rawgeti(s->ctx, LUA_REGISTRYINDEX, s->cb);
	new l_packet_ref(p, s->ctx);
	int err = lua_pcall(s->ctx, 1, 1, err_handler);
	if (err) {
		std::cerr << "Error in the callback: " << luaL_checkstring(s->ctx, -1) << std::endl;
		lua_pop(s->ctx, 2);
		return -1;
	}
	if (!lua_isnumber(s->ctx, -1)) {
		lua_pop(s->ctx, 2);
		return 0;
	}
	int ret = lua_tonumber(s->ctx, -1);
	lua_pop(s->ctx, 2);
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
	TbxSniffer *s = new TbxSniffer(key);
	new l_sniffer_ref(s, l);
	return 1;
}
/***
 * The callback function for the sniffer
 * @function sniffer_callback
 * @tparam Packet pkt the received packet
 * @treturn num x any value but 0 will stop the Sniffer
 */

/***
 * Start sniffing and calls the callback function for each new packet.
 * Will never return unless @{stop} is called from another thread or if
 * it was started in non-blocking mode.
 * @function start
 * @tparam[opt] function cb a function callback, see @{sniffer_callback},
 * to operate in blokcing mode. Omit to be non-blocking.
 */
int l_sniffer_ref::l_start(lua_State *l)
{
	l_sniffer_ref *s = dynamic_cast<l_sniffer_ref *>(l_sniffer_ref::get_instance(l, 1));
	if (!s)
		return luaL_argerror(l, 1, "The parameter is not a real sniffer instance!");
	s->ctx = l;
	if (lua_gettop(l) == 1) {
		s->ref->start();
	} else {
		luaL_checktype(l, 2, LUA_TFUNCTION);
		s->cb = luaL_ref(l, LUA_REGISTRYINDEX);
		s->ref->start(l_sniffer_cb, s);
		luaL_unref(s->ctx, LUA_REGISTRYINDEX, s->cb);
	}
	return 0;
}

/***
 * Stop sniffing
 * @function stop
 */
int l_sniffer_ref::l_stop(lua_State *l)
{
	TbxSniffer *s = l_sniffer_ref::extract(l, 1);
	s->stop();
	return 0;
}

/***
 * Receive a packet
 * @function recv
 * @tparam[opt] num timeout number of second to wait, can be decimal, or omit to block
 * @treturn Packet p the received packet, or nil if timed out
 */
int l_sniffer_ref::l_recv(lua_State *l)
{
	TbxSniffer *s = l_sniffer_ref::extract(l, 1);
	Crafter::Packet *p;
	if (lua_gettop(l) > 1) {
		double tmout = l_data_type<double>::extract(l, 2);
		struct timespec ts = {(long)tmout, (long)(tmout * 10e9)};
		p = s->recv(&ts);
	} else {
		p = s->recv(NULL);
	}
	if (p){
		new l_packet_ref(p, l);
		writePcap(p);
	}else
		lua_pushnil(l);
	return 1;
}

void l_sniffer_ref::register_members(lua_State *l)
{
	l_ref<TbxSniffer>::register_members(l);
	meta_bind_func(l, "new", l_Sniffer);
	meta_bind_func(l, "start", l_start);
	meta_bind_func(l, "stop", l_stop);
	meta_bind_func(l, "recv", l_recv);
}
