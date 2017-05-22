/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_BASE_HPP_
#define __LUA_BASE_HPP_


#include <memory>
#include <crafter.h>

#define LUA_COMPAT_ALL
#include <lua.hpp>
#include <lua.h>

#include "config.h"

#ifndef HAVE_LUA_PUSHGLOBALTABLE
#define lua_pushglobaltable(L) lua_pushvalue(L, LUA_GLOBALSINDEX)
#endif

extern int lua_traceback(lua_State *l);
extern void stackDump (lua_State *L, const char* file, size_t line,
		std::ostream& out);
#define L_DUMP_STACK(l) stackDump(l, __FILE__, __LINE__, std::cerr)

extern void l_do(lua_State *l, const char*);

extern const char *l_classname_field;

/* Wrapper around lua types */
template<typename T>
struct l_data_type {
		T val;

		l_data_type() : val() {}
		virtual ~l_data_type() {}
		l_data_type(const T& v) : val(v) {}
		l_data_type& operator=(const T& v) { val = v; return *this; }
		l_data_type& operator=(const l_data_type<T>& v) { val = v; return *this; }
		operator T() const { return val; }
		void push(lua_State *l);
		static T extract(lua_State *l, int n);
};

/* Assumes a (meta)table is on top of the stack */
template<class C>
void metatable_bind(lua_State *l, const char *key, l_data_type<C> data)
{
	data.push(l);
	lua_setfield(l, -2, key);
}
extern void meta_bind_func(lua_State *l, const char *key, lua_CFunction f);

template<class C>
struct tname {
	static const char *name;
};

#define TNAME(C) tname<C>::name
#define L_EXPOSE_TYPE_AS(x,y) template<> const char *tname<x>::name = #y
#define L_EXPOSE_TYPE(x) L_EXPOSE_TYPE_AS(x,x)

struct lua_base {
	virtual void debug(std::ostream &out) = 0;
	virtual ~lua_base() {};
};

/* Base wrapper class to expose cpp object pointers to lua.
 * The lua object takes ownership of the pointer through a shread pointer */
template<class C>
struct l_ref : public lua_base {
	/* Lua Class name */
	const char *c_name;

	/* The data we want to expose */
	C* ref;
	/* The actual owner of it (possibly itself,
	 * or eg. the Packet holding the Layer) */
	std::shared_ptr<void> owner;

	/* New Lua object */
	l_ref(C *instance, lua_State *l, const char *classname = TNAME(C))
		: c_name(classname), ref(instance), owner(instance)
	{
		push(l);
	}
	/* Copy existing object */
	l_ref(std::shared_ptr<C> ref, lua_State *l,
			const char *classname = TNAME(C))
		: c_name(classname), ref(ref.get()), owner(ref)
	{
		push(l);
	}
	/* Register dependent objects */
	l_ref(C *instance, std::shared_ptr<void> owner, lua_State *l,
			const char *classname = TNAME(C))
		: c_name(classname), ref(instance), owner(owner)
	{
		push(l);
	}

	static C* new_ref(lua_State *l)
	{
		return (new l_ref(new C(), l))->ref;
	}

	operator C*() { return ref; }

	virtual void debug(std::ostream &out)
	{
		out << "[" << TNAME(C) << "] ";
	}

	C& operator* () { return *this->ref; }
    C* operator-> () { return this->ref; }

	l_ref& operator=(const l_ref& v)
	{
		if (this != &v) {
			this->ref = v.ref;
		}
		return *this;
	}
	l_ref& operator=(const l_ref* v) { return this->operator=(*v); }


	void push(lua_State *l)
	{
		l_ref **udata = static_cast<l_ref **>(
				lua_newuserdata(l, sizeof(l_ref *)));
		*udata = this;
		luaL_getmetatable(l, c_name);
		lua_setmetatable(l, -2);
	}

	static C* extract(lua_State *l, int n)
	{
		return get_instance(l, n)->ref;
	}

	template<class K>
	static std::shared_ptr<K> get_owner(lua_State *l, int n)
	{
		return std::static_pointer_cast<K>(get_instance(l, n)->owner);
	}

	static l_ref* get_instance(lua_State *l, int n)
	{
		return *static_cast<l_ref **>(luaL_checkudata(l, n, TNAME(C)));
	}

	static int destroy(lua_State *l)
	{
		delete get_instance(l, 1);
		return 0;
	}

	/* Called to initialize this reference kind metatable */
	static void register_members(lua_State *l)
	{
		metatable_bind<const char*>(l, l_classname_field,
				l_data_type<const char*>(TNAME(C)));
		meta_bind_func(l, "__gc", destroy);
	}

	/* Called once all types have registered */
	static void register_globals(lua_State *l) { (void)l; }

protected:
	virtual ~l_ref() {}
};

#endif
