#ifndef __LUA_BASE_HPP_
#define __LUA_BASE_HPP_


#include <crafter.h>

#define LUA_COMPAT_ALL
#include <lua.hpp>

void stackDump (lua_State *L, const char* file, size_t line);
#define L_DUMP_STACK(l) stackDump(l, __FILE__, __LINE__)

void l_do(lua_State *l, const char*);

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
void meta_bind_func(lua_State *l, const char *key, lua_CFunction f);

template<class C>
struct tname {
	public:
	static const char *name;
};
#define TNAME(C) tname<C>::name
#define L_EXPOSE_TYPE(x) template<> const char *tname<x>::name = #x

/* Base wrapper class to expose cpp object pointers to lua */
template<class C>
struct l_ref : public l_data_type<C*> {
	int key;
	lua_State *l;

	l_ref() : l_data_type<C*>(NULL) {}
	/* Acquire ownership of i */
	l_ref(C *instance, lua_State *l)
		: l_data_type<C*>(instance), key(LUA_NOREF), l(l) { push(l); }
	/* Reference an owner of i, and copy its instance pointer
	 * Assumes that ref is on top of the stack!
	 * */
	template<class T>
	l_ref(l_ref<T> *ref, C *i)
		: l_data_type<C*>(i), key(luaL_ref(ref->l, LUA_REGISTRYINDEX)), l(ref->l)
		{ push(l); }

	static C* new_ref(lua_State *l)
	{
		C *o = new C();
		new l_ref(o, l);
		return o;
	}

	virtual ~l_ref()
	{
		/* Delete the instance if we own it */
		if (key == LUA_NOREF)
			delete this->val;
		else
			/* Otherwise just unref the owner to allow it to be GCed */
			luaL_unref(l, LUA_REGISTRYINDEX, key);
	}

	virtual void debug(std::ostream &out)
	{
		out << "[" << TNAME(C) << "]";
	}

	l_ref& operator=(const l_ref& v)
	{
		if (key != LUA_NOREF)
			luaL_unref(l, LUA_REGISTRYINDEX, key);
		else if (this->val)
			delete this->val;

		key = luaL_ref(v.l, LUA_REGISTRYINDEX);
		l = v.l;
		return l_data_type<C*>::operator=(v.i);
	}
	l_ref& operator=(const l_ref* v) { return this->operator=(*v); }

	void push(lua_State *l)
	{
		this->l = l;
		l_ref **udata = static_cast<l_ref **>(
				lua_newuserdata(l, sizeof(l_ref *)));
		*udata = this;
		luaL_getmetatable(l, TNAME(C));
		lua_setmetatable(l, -2);
	}

	static C* get(lua_State *l, int n) { return get_instance(l, n)->val; }
	static l_ref* get_instance(lua_State *l, int n)
	{
		return *static_cast<l_ref **>(luaL_checkudata(l, n, TNAME(C)));
	}

	static int destroy(lua_State *l)
	{
		l_ref *r = l_ref::get_instance(l, 1);
		r->l = l;
		delete r;
		return 0;
	}

	/* Called to initialize this reference kind metatable */
	static void register_members(lua_State *l)
	{
		meta_bind_func(l, "__gc", destroy);
	}

	/* Called once all types have registered */
	static void register_globals(lua_State *l) { (void)l; }
};

#endif
