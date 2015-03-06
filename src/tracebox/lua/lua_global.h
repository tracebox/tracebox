#ifndef __LUA_GLOBAL_H_
#define __LUA_GLOBAL_H_

#include "lua_base.hpp"
#include "lua_crafter.hpp"
#include "lua_fwfilter.h"
#include "lua_icmp.h"
#include "lua_ip.h"
#include "lua_ipoption.h"
#include "lua_ipv6.h"
#include "lua_ipv6segmentroutingheader.h"
#include "lua_packetmodifications.h"
#include "lua_raw.h"
#include "lua_tcp.h"
#include "lua_tcpoption.h"
#include "lua_udp.h"


extern lua_State *l_init();

extern int l_Tracebox(lua_State *l);


#endif
