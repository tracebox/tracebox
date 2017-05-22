/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_CRAFTER_HPP_
#define __LUA_CRAFTER_HPP_

#include "lua_base.hpp"
#include <cstring>
#include <unordered_map>

struct lua_tbx {
	static const char *base_class_field;
	static int l_concat(lua_State *l);
	static std::unordered_map<int, const char*> *l_layer_ref_mapping;


	template<class Base>
	static Base* get_udata(lua_State *l, int n)
	{
		luaL_checktype(l, n, LUA_TUSERDATA);
		/* We want a custom data type */
		if (!luaL_getmetafield(l, n, base_class_field))
			return NULL;
		/* We want the object the have the specified base class name */
		const char *basename = l_data_type<const char*>::extract(l, -1);
		lua_pop(l, 1);
		if (strcmp(TNAME(Base), basename))
			return NULL;
		return (*static_cast<l_ref<Base>**>(lua_touserdata(l, n)))->ref;
	};
};

template<class C>
int push_streamfunc(lua_State *l, void (C::*f)(std::ostream&))
{
	std::ostringstream stream;
	C *o = l_ref<C>::extract(l, 1);
	(o->*f)(stream);
	l_data_type<std::string>(stream.str()).push(l);
	return 1;
}
template<class C>
int push_streamfunc(lua_State *l, void (C::*f)(std::ostream&) const)
{
	std::ostringstream stream;
	C *o = l_ref<C>::extract(l, 1);
	(o->*f)(stream);
	l_data_type<std::string>(stream.str()).push(l);
	return 1;
}

/* Generic setter/getter */
template<typename T, class C, class B, void (B::*setfunc)(const T&)>
static int setter(lua_State *l)
{
	C *o = l_ref<C>::extract(l, 1);
	(o->*setfunc)(l_data_type<T>::extract(l, 2));
	return 0;
};
#define L_SETTER_BASE(type, class_name, base_class, field_name) \
	setter<type, class_name, base_class, &base_class::Set##field_name>
#define L_SETTER(type, class_name, field_name) \
	L_SETTER_BASE(type, class_name, class_name, field_name)

template<typename T, class C, class B, T (B::*getfunc)() const>
static int getter(lua_State *l)
{
	C *o = l_ref<C>::extract(l, 1);
	l_data_type<T>((o->*getfunc)()).push(l);
	return 1;
};
#define L_GETTER_BASE(type, class_name, base_class, field_name) \
	getter<type, class_name, base_class, &base_class::Get##field_name>
#define L_GETTER(type, class_name, field_name) \
	L_GETTER_BASE(type, class_name, class_name, field_name)


template<typename T, class C, class B, T(B::*getfunc)() const, void (B::*setfunc)(const T&)>
static int accessor(lua_State *l)
{
	if (lua_gettop(l) > 1)
		setter<T, C, B, setfunc>(l);
	else
		getter<T, C, B, getfunc>(l);
	return 1; /* Either we keep the parameter or we pushed the value */
};
#define L_ACCESSOR_BASE(type, class_name, base_class, field_name) \
	accessor<type, class_name, base_class, \
		&base_class::Get##field_name, &base_class::Set##field_name>
#define L_ACCESSOR(type, class_name, field_name) \
	L_ACCESSOR_BASE(type, class_name, class_name, field_name)

/* Legacy bindings ... do not use */
#define META_GETTER_SETTER(l, name, type, class_name, field_name) \
	do { \
		meta_bind_func(l, "set" #name, L_SETTER(type, class_name, field_name)); \
		meta_bind_func(l, "get" #name, L_GETTER(type, class_name, field_name)); \
	} while (0)

template<class C>
struct l_crafter_ref : public l_ref<C> {
	using l_ref<C>::l_ref;


	void debug(std::ostream& out)
	{
		l_ref<C>::debug(out);
		out << (void*) this << " ";
		this->ref->Print(out);
	}

	/* Base Print/HexDump methods */
	static int print(lua_State *l){ return push_streamfunc<C>(l, &C::Print); }
	static int hexdump(lua_State *l) { return push_streamfunc<C>(l, &C::HexDump); }

	static int l_concat(lua_State *l);

	template<class Base>
	static void register_members(lua_State *l)
	{
		l_ref<C>::register_members(l);
		metatable_bind<const char*>(l, lua_tbx::base_class_field, TNAME(Base));
		meta_bind_func(l, "__concat", lua_tbx::l_concat);
		meta_bind_func(l, "__add", lua_tbx::l_concat);
		meta_bind_func(l, "__div", lua_tbx::l_concat);
		meta_bind_func(l, "__tostring", print);
		meta_bind_func(l, "print", print);
		meta_bind_func(l, "hexdump", hexdump);
		meta_bind_func(l, "size", getter<size_t, Base, Base, &Base::GetSize>);
	}

	static void register_globals(lua_State *l) { l_ref<C>::register_globals(l); }

	protected:
	virtual ~l_crafter_ref() {}
};

template<class C>
int set_payload(lua_State *l)
{
	C *o = l_crafter_ref<C>::extract(l, 1);
	o->SetPayload(l_data_type<const char*>::extract(l, 2));
	return 0;
}
#endif
