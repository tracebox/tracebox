/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __LUA_CRAFTER_HPP_
#define __LUA_CRAFTER_HPP_

#include "lua_base.hpp"

struct lua_tbx {
	static const char *base_class_field;
	static int l_concat(lua_State *l);
};

template<class C>
int push_streamfunc(lua_State *l, void (C::*f)(std::ostream&))
{
	std::ostringstream stream;
	C *o = l_ref<C>::get(l, 1);
	(o->*f)(stream);
	l_data_type<std::string>(stream.str()).push(l);
	return 1;
}
template<class C>
int push_streamfunc(lua_State *l, void (C::*f)(std::ostream&) const)
{
	std::ostringstream stream;
	C *o = l_ref<C>::get(l, 1);
	(o->*f)(stream);
	l_data_type<std::string>(stream.str()).push(l);
	return 1;
}

template<class C>
struct l_crafter_ref : public l_ref<C> {
	using l_ref<C>::l_ref;

	void debug(std::ostream& out)
	{
		l_ref<C>::debug(out);
		out << (void*) this << " ";
		this->val->Print(out);
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
	}

	static void register_globals(lua_State *l) { l_ref<C>::register_globals(l); }

	protected:
	virtual ~l_crafter_ref() {}
};

template<class C>
struct l_layer_ref : public l_crafter_ref<C> {
	using l_crafter_ref<C>::l_crafter_ref;

	/* Generic setter/getter */
	template<typename T, void (C::*setfunc)(const T&)>
	static int setter(lua_State *l)
	{
		C *o = l_layer_ref<C>::get(l, 1);
		(o->*setfunc)(l_data_type<T>::get(l, 2));
		return 0;
	};
	#define L_SETTER(type, class_name, field_name) \
		setter<type, &class_name::Set##field_name>

	template<typename T, T (C::*getfunc)() const>
	static int getter(lua_State *l)
	{
		C *o = l_layer_ref<C>::get(l, 1);
		l_data_type<T>((o->*getfunc)()).push(l);
		return 1;
	};
	#define L_GETTER(type, class_name, field_name) \
		getter<type, &class_name::Get##field_name>

	#define META_GETTER_SETTER(l, name, type, class_name, field_name) \
		do { \
			meta_bind_func(l, "set" #name, L_SETTER(type, class_name, field_name)); \
			meta_bind_func(l, "get" #name, L_GETTER(type, class_name, field_name)); \
		} while (0)

	static void register_members(lua_State *l)
	{
		l_crafter_ref<C>::template register_members<Crafter::Layer>(l);
	}

	protected:
	virtual ~l_layer_ref() {}
};

template<class C>
int set_payload(lua_State *l)
{
	C *o = l_crafter_ref<C>::get(l, 1);
	o->SetPayload(l_data_type<const char*>::get(l, 2));
	return 0;
}
#endif
