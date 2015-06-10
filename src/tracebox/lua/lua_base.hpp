/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_BASE_HPP_
#define __LUA_BASE_HPP_


#include <crafter.h>

#define LUA_COMPAT_ALL
#include <lua.hpp>
#include <lua.h>

#include "config.h"

#ifndef HAVE_LUA_PUSHGLOBALTABLE
#define lua_pushglobaltable(L) lua_pushvalue(L, LUA_GLOBALSINDEX)
#endif

extern int lua_traceback(lua_State *l);
extern void stackDump (lua_State *L, const char* file, size_t line, std::ostream& out);
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
		static T get(lua_State *l, int n);
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
#define L_EXPOSE_TYPE(x) template<> const char *tname<x>::name = #x

struct _ref_count {
	size_t c;

	_ref_count() : c(0) {}
	void inc() { ++c; }
	size_t dec() { return --c; }
};

struct _ref_base {
	static size_t instance_count;

	_ref_count *ref;

	_ref_base() : ref(new _ref_count) { retain(); ++instance_count; }
	_ref_base(const _ref_base& r) : ref(r.ref) { retain(); ++instance_count; }

	void retain() { ref->inc(); }
	void release()
	{
		if (!ref->dec()) {
			this->cleanup();
			delete this;
		}
	}

	virtual void debug(std::ostream&) {}

	_ref_base& operator=(const _ref_base& v)
	{
		if (this != &v) {
			if (!ref->dec())
				this->cleanup();
			ref = v.ref;
			ref->inc();
		}
		return *this;
	}

	protected:
	virtual void cleanup() { delete ref; ref = NULL; };

	protected: /* use release()/cleanup() instead */
	virtual ~_ref_base() { --instance_count; if (ref) delete ref; }
};

/* Base wrapper class to expose cpp object pointers to lua */
template<class C>
struct l_ref : public _ref_base {
	C *val;
	/* Original owner of the pointer, if its not ourselves */
	_ref_base *owner_ref;
	/* Lua Class name */
	const char *c_name;

	/* Empty reference */
	l_ref() : val(NULL), owner_ref(NULL), c_name(TNAME(C)) {}
	/* New reference */
	l_ref(C *instance, lua_State *l, const char *classname = TNAME(C))
		: val(instance), owner_ref(NULL), c_name(classname)
	{
		_push_noretain(l);
	}
	/* Copy reference */
	l_ref(l_ref *r, lua_State *l, const char *classname = TNAME(C))
			: _ref_base(*r), val(r->val), owner_ref(r->owner_ref), c_name(classname)
	{
		if (owner_ref)
			owner_ref->retain();
		_push_noretain(l);
	}
	/* New reference, and register dependance to other one */
	template<class T>
	l_ref(l_ref<T> *r, C *i, lua_State *l, const char *classname = TNAME(C))
		: val(i), owner_ref(r), c_name(classname)
	{
		owner_ref->retain();
		_push_noretain(l);
	}

	operator C*() { return val; }

	static C* new_ref(lua_State *l)
	{
		C *o = new C();
		new l_ref(o, l);
		return o;
	}

	virtual void debug(std::ostream &out)
	{
		out << "[" << TNAME(C) << "] ";
	}

	C& operator* () { return *this->val; }
    C* operator-> () { return this->val; }

	l_ref& operator=(const l_ref& v)
	{
		_ref_base::operator=(v);
		if (this != &v) {
			this->val = v.val;
			owner_ref = v.owner_ref;
			if (owner_ref)
				owner_ref->retain();
		}
		return *this;
	}
	l_ref& operator=(const l_ref* v) { return this->operator=(*v); }


	void push(lua_State *l)
	{
		retain();
		_push_noretain(l);
	}

	static C* get(lua_State *l, int n) { return (C*)get_instance(l, n)->val; }
	static l_ref* get_instance(lua_State *l, int n)
	{
		return *static_cast<l_ref **>(luaL_checkudata(l, n, TNAME(C)));
	}

	static int destroy(lua_State *l)
	{
		l_ref::get_instance(l, 1)->release();
		return 0;
	}

	/* Called to initialize this reference kind metatable */
	static void register_members(lua_State *l)
	{
		metatable_bind<const char*>(l, l_classname_field, l_data_type<const char*>(TNAME(C)));
		meta_bind_func(l, "__gc", destroy);
		meta_bind_func(l, "__cpp_ref_count", _get_ref_count);
		meta_bind_func(l, "__cpp_ownerref_count", _get_ownerref_count);
	}

	/* Called once all types have registered */
	static void register_globals(lua_State *l) { (void)l; }

	static int _get_ref_count(lua_State *l)
	{
		l_ref *r = get_instance(l, 1);
		lua_pushnumber(l, r->ref->c);
		return 1;
	}

	static int _get_ownerref_count(lua_State *l)
	{
		l_ref *r = get_instance(l, 1);
		if (r->owner_ref)
			lua_pushnumber(l, r->owner_ref->ref->c);
		else
			lua_pushnil(l);
		return 1;

	}

protected:
	virtual ~l_ref() {}

	void cleanup()
	{
		/* Check if we own our val pointer, thus can delete it */
		if (!owner_ref) {
			delete this->val;
			_ref_base::cleanup();
		} else { /* Release our reference towards the true owner otherwise*/
			owner_ref->release();
		}
	}

private: /* Use release() to get here */
	void _push_noretain(lua_State *l)
	{
		l_ref **udata = static_cast<l_ref **>(lua_newuserdata(l, sizeof(l_ref *)));
		*udata = this;
		luaL_getmetatable(l, c_name);
		lua_setmetatable(l, -2);
	}
};

#endif
