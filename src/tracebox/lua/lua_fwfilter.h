#ifndef __LUA_FWFilter_H_
#define __LUA_FWFilter_H_

#include "lua_crafter.hpp"

class FWFilter {
	int src, dst, id;
public:
	FWFilter(int src, int dst);

	~FWFilter() { close(); }

	void close();
};

struct l_fwfilter_ref : public l_ref<FWFilter> {
	l_fwfilter_ref (FWFilter *i, lua_State *l) : l_ref<FWFilter>(i, l) {}
	template<class T>
	l_fwfilter_ref (l_ref<T> *r, FWFilter *i) : l_ref<FWFilter>(r, i) {}
	~l_fwfilter_ref () {}

	static int l_FWFilter_close(lua_State *l);
	static int l_TraceboxFilter(lua_State *l);
	static void register_members(lua_State *l);
	static void register_globals(lua_State *l);
};

#endif
