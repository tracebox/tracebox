#include "lua_packetmodifications.h"
#include "lua_arg.h"
#include "../tracebox.h"

struct tracebox_info {
	const char *cb;
	lua_State *l;
	Packet *rcv;
};

static int tCallback(void *ctx, int ttl, std::string& ip,
	const Packet * const probe, Packet *rcv, PacketModifications *mod)
{
	struct tracebox_info *info = (struct tracebox_info *)ctx;
	int ret;

	info->rcv = rcv;

	if (!info->cb)
		return 0;

	lua_getglobal(info->l, info->cb);
	if(lua_type(info->l, -1) != LUA_TFUNCTION) {
		const char* msg = lua_pushfstring(info->l, "`%s' is not a function", info->cb);
		luaL_argerror(info->l, -1, msg);
		return -1;
	}

	l_data_type<int>(ttl).push(info->l);

	if (ip == "")
		lua_pushnil(info->l);
	else
		l_data_type<std::string>(ip).push(info->l);

	new l_packet_ref((Packet *)probe, info->l);

	l_packet_ref *rcv_ref = NULL;
	if (!rcv)
		lua_pushnil(info->l);
	else
		rcv_ref = new l_packet_ref((Packet *)rcv, info->l);

	if (!mod)
		lua_pushnil(info->l);
	else if (rcv_ref) {
		rcv_ref->push(info->l); /* Will be popped when creating the reference */
		new l_packetmodifications_ref(rcv_ref, mod);
	} else
		new l_packetmodifications_ref(mod, info->l);

	int err = lua_pcall(info->l, 5, 1, 0);
	if (err) {
		std::cerr << "Error in the callback: " << luaL_checkstring(info->l, -1) << std::endl;
		lua_pop(info->l, 1);
		return -1;
	}
	if (!lua_isnumber(info->l, -1)) {
		lua_pop(info->l, 1);
		return 0;
	}
	ret = lua_tonumber(info->l, -1);
	lua_pop(info->l, 2);
	return ret;
}

int l_Tracebox(lua_State *l)
{
	static struct tracebox_info info = {NULL, l, NULL};
	std::string err;
	int ret = 0;
	bool cb_set = false;
	Packet *pkt = l_packet_ref::get(l, 1);
	if (!pkt) {
		std::cerr << "doTracebox: no packet!" << std::endl;
		return 0;
	}

	if (lua_gettop(l) == 1)
		goto no_args;

	cb_set = v_arg_string_opt(l, 2, "callback", &info.cb);

no_args:
	ret = doTracebox(pkt, tCallback, err, &info);
	if (ret < 0) {
		const char* msg = lua_pushfstring(l, "Tracebox error: %s", err.c_str());
		luaL_argerror(l, -1, msg);
		return 0;
	}

	/* Did the server reply ? */
	if (ret == 1 && info.rcv)
		new l_packet_ref((Packet *)info.rcv, l);
	else
		lua_pushnil(l);

	return 1;
}
