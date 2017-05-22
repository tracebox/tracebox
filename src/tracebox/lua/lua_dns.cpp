/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "lua_dns.h"
#include "lua_arg.h"

using namespace Crafter;

/***
 * The DNS Layer
 * @classmod DNS
 */
/***
 * Create a new DNS Layer
 * @function new
 * @tparam[opt] table args see new_args
 * @treturn DNS dns
 */
/***
 * DNS Layer constructor arguments
 * @table new_args
 * @tfield num id DNS identification number
 * @tfield num opcode see @{OpCode}
 * @tfield num rcode see @{RCode}
 * @tfield bool qr
 * @tfield bool aa
 * @tfield bool tc
 * @tfield bool rd
 * @tfield bool ra
 * @tfield bool zf
 * @tfield bool ad
 */
int l_dns_ref::l_DNS(lua_State *l)
{
	int identification, opcode, rcode;
	bool qr, aa, tc, rd, ra, z, ad;
	qr = aa = tc = rd = ra = z = ad = false;
	bool id = v_arg_integer_opt(l, 1, "id", &identification);
	bool op = v_arg_integer_opt(l, 1, "opcode", &opcode);
	bool r = v_arg_integer_opt(l, 1, "rcode", &rcode);
	v_arg_boolean_opt(l, 1, "qr", &qr);
	v_arg_boolean_opt(l, 1, "aa", &aa);
	v_arg_boolean_opt(l, 1, "tc", &tc);
	v_arg_boolean_opt(l, 1, "rd", &rd);
	v_arg_boolean_opt(l, 1, "ra", &ra);
	v_arg_boolean_opt(l, 1, "z", &z);
	v_arg_boolean_opt(l, 1, "ad", &ad);

	DNS *dns = l_dns_ref::new_ref(l);
	if (id) dns->SetIdentification(identification);
	if (op) dns->SetOpCode(opcode);
	if (r) dns->SetRCode(rcode);
	dns->SetQRFlag(qr);
	dns->SetAAFlag(aa);
	dns->SetTCFlag(tc);
	dns->SetRDFlag(rd);
	dns->SetRAFlag(ra);
	dns->SetZFlag(z);
	dns->SetADFlag(ad);

	return 1;
}

/***
 * Add a query to the DNS Layer
 * @function add_query
 * @tparam DNSQuery query
 */
int l_dns_ref::l_add_query(lua_State *l)
{
	DNS *dns = l_dns_ref::extract(l, 1);
	DNS::DNSQuery *query = l_dnsquery_ref::extract(l, 2);
	dns->Queries.push_back(*query);
	return 0;
}

/***
 * Add an answer to the DNS Layer
 * @function add_answer
 * @tparam DNSAnswer answer
 */
int l_dns_ref::l_add_answer(lua_State *l)
{
	DNS *dns = l_dns_ref::extract(l, 1);
	DNS::DNSAnswer *answer = l_dnsanswer_ref::extract(l, 2);
	dns->Answers.push_back(*answer);
	return 0;
}

/***
 * Add an authority answer to the DNS Layer
 * @function add_authority
 * @tparam DNSAnswer authority
 */
int l_dns_ref::l_add_authority(lua_State *l)
{
	DNS *dns = l_dns_ref::extract(l, 1);
	DNS::DNSAnswer *answer = l_dnsanswer_ref::extract(l, 2);
	dns->Authority.push_back(*answer);
	return 0;
}

/***
 * Add an answer in the additional section of the DNS Layer
 * @function add_additional
 * @tparam DNSAnswer additional
 */
int l_dns_ref::l_add_additional(lua_State *l)
{
	DNS *dns = l_dns_ref::extract(l, 1);
	DNS::DNSAnswer *answer = l_dnsanswer_ref::extract(l, 2);
	dns->Authority.push_back(*answer);
	return 0;
}


template<class C>
void l_dns_ref::push_vector(lua_State *l, std::vector<C> &v)
{
	int i = 1;
	lua_newtable(l);
	for (auto &val : v) {
		new l_ref<C>(&val, this->owner, l);
		lua_rawseti(l, -2, i);
		++i;
	}
}

/***
 * List all queries found in the Layer
 * @function queries
 * @treturn table queries a list of @{DNSQuery}
 */
int l_dns_ref::l_queries(lua_State *l)
{
	l_dns_ref *ref = dynamic_cast<l_dns_ref*>(l_dns_ref::get_instance(l, 1));
	if (!ref)
		return luaL_argerror(l, 1, "Parameter is not a DNS Layer");
	ref->push_vector<DNS::DNSQuery>(l, ref->ref->Queries);
	return 1;
}

/***
 * List all answers found in the Layer
 * @function answers
 * @treturn table answers a list of @{DNSAnswer}
 */
int l_dns_ref::l_answers(lua_State *l)
{
	l_dns_ref *ref = dynamic_cast<l_dns_ref*>(l_dns_ref::get_instance(l, 1));
	if (!ref)
		return luaL_argerror(l, 1, "Parameter is not a DNS Layer");
	ref->push_vector<DNS::DNSAnswer>(l, ref->ref->Answers);
	return 1;
}

/***
 * List all answers found in the Layer
 * @function authority
 * @treturn table authority a list of @{DNSAnswer}
 */
int l_dns_ref::l_authority(lua_State *l)
{
	l_dns_ref *ref = dynamic_cast<l_dns_ref*>(l_dns_ref::get_instance(l, 1));
	if (!ref)
		return luaL_argerror(l, 1, "Parameter is not a DNS Layer");
	ref->push_vector<DNS::DNSAnswer>(l, ref->ref->Authority);
	return 1;
}

/***
 * List all answers found in the Layer
 * @function additional
 * @treturn table additional a list of @{DNSAnswer}
 */
int l_dns_ref::l_additional(lua_State *l)
{
	l_dns_ref *ref = dynamic_cast<l_dns_ref*>(l_dns_ref::get_instance(l, 1));
	if (!ref)
		return luaL_argerror(l, 1, "Parameter is not a DNS Layer");
	ref->push_vector<DNS::DNSAnswer>(l, ref->ref->Additional);
	return 1;
}

void l_dns_ref::register_members(lua_State *l)
{
	l_layer_ref<DNS>::register_members(l);
	meta_bind_func(l, "new", l_DNS);
	meta_bind_func(l, "add_query", l_add_query);
	meta_bind_func(l, "add_answer", l_add_answer);
	meta_bind_func(l, "add_authority", l_add_authority);
	meta_bind_func(l, "add_additional", l_add_additional);
	meta_bind_func(l, "queries", l_queries);
	meta_bind_func(l, "answers", l_answers);
	meta_bind_func(l, "authority", l_authority);
	meta_bind_func(l, "additional", l_additional);
	/***
	 * Get the DNS identification value
	 * @function id
	 * @treturn num id
	 */
	meta_bind_func(l, "id", L_GETTER(short_word, DNS, Identification));
	/***
	 * Get the DNS OpCode
	 * @function opcode
	 * @treturn num opcode
	 */
	meta_bind_func(l, "id", L_GETTER(word, DNS, OpCode));
	/***
	 * Get the DNS Return Code
	 * @function rcode
	 * @treturn num rcode
	 */
	meta_bind_func(l, "rcode", L_GETTER(word, DNS, RCode));
	/***
	 * Get the DNS QR flag
	 * @function qr
	 * @treturn num qr
	 */
	meta_bind_func(l, "qr", L_GETTER(word, DNS, QRFlag));
	/***
	 * Get the DNS AA flag
	 * @function aa
	 * @treturn num aa
	 */
	meta_bind_func(l, "aa", L_GETTER(word, DNS, AAFlag));
	/***
	 * Get the DNS TC flag
	 * @function tc
	 * @treturn num tc
	 */
	meta_bind_func(l, "tc", L_GETTER(word, DNS, TCFlag));
	/***
	 * Get the DNS RD flag
	 * @function rd
	 * @treturn num rd
	 */
	meta_bind_func(l, "rd", L_GETTER(word, DNS, RDFlag));
	/***
	 * Get the DNS RA flag
	 * @function ra
	 * @treturn num ra
	 */
	meta_bind_func(l, "ra", L_GETTER(word, DNS, RAFlag));
	/***
	 * Get the DNS Z flag
	 * @function z
	 * @treturn num z
	 */
	meta_bind_func(l, "z", L_GETTER(word, DNS, ZFlag));
	/***
	 * Get the DNS AD flag
	 * @function ad
	 * @treturn num ad
	 */
	meta_bind_func(l, "ad", L_GETTER(word, DNS, ADFlag));
	/***
	 * Get the DNS CD flag
	 * @function cd
	 * @treturn num cd
	 */
	meta_bind_func(l, "cd", L_GETTER(word, DNS, CDFlag));
#define CST(prefix, key) do {\
	l_data_type<int>(DNS::prefix##key).push(l);\
	lua_setfield(l, -2, #key);\
	} while (0)
	/***
	 * Pre-defined DNS OpCodes
	 * @table OpCode
	 * @field Query
	 * @field IQuery
	 * @field Status
	 * @field Notify
	 * @field Update
	 * @usage DNS.OpCode.Query
	 */
	lua_newtable(l);
#define _OP(x) CST(OpCode, x)
	_OP(Query);
	_OP(IQuery);
	_OP(Status);
	_OP(Notify);
	_OP(Update);
	lua_setfield(l, -2, "OpCode");
	/***
	 * Pre-defined DNS Return Codes
	 * @table RCode
	 * @field NoError
	 * @field FormatError
	 * @field ServerFailure
	 * @field NameError
	 * @field Refused
	 * @field YXDomain
	 * @field YXRRSet
	 * @field NXRRSet
	 * @field NotAuth
	 * @field NotZone
	 * @usage if dns:rcode() == DNS.RCode then ... end
	 */
	lua_newtable(l);
#define _R(x) CST(RCode, x)
	_R(NoError);
	_R(FormatError);
	_R(ServerFailure);
	_R(NameError);
	_R(Refused);
	_R(YXDomain);
	_R(YXRRSet);
	_R(NXRRSet);
	_R(NotAuth);
	_R(NotZone);
	lua_setfield(l, -2, "RCode");
	/***
	 * Pre-defined DNS Types
	 * @table Type
	 * @field A
	 * @field AAAA
	 * @field NS
	 * @field CNAME
	 * @field SOA
	 * @field WKS
	 * @field PTR
	 * @field MX
	 * @field SRV
	 * @field A6
	 * @field OPT
	 * @field ANY
	 * @usage DNS.Type.A
	 */
	lua_newtable(l);
#define _T(x) CST(Type, x)
	_T(A);
	_T(AAAA);
	_T(NS);
	_T(CNAME);
	_T(SOA);
	_T(WKS);
	_T(PTR);
	_T(MX);
	_T(SRV);
	_T(A6);
	_T(OPT);
	_T(ANY);
	lua_setfield(l, -2, "Type");
	/***
	 * Pre-defined DNS Class
	 * @table Class
	 * @field IN
	 * @usage DNS.Class.IN
	 */
	lua_newtable(l);
#define _CL(x) CST(Class, x)
	_CL(IN);
	lua_setfield(l, -2, "Class");
}

/***
 * A DNS Query
 * @type DNSQuery
 */
/***
 * Create a new DNS query
 * @function new
 * @tparam table args arguments, see @{new_args}
 */
/***
 * Constructor arguments
 * @table new_args
 * @tfield string name
 * @tfield num type see @{DNS.Type}
 * @tfield num class see @{DNS.Class}
 * @treturn DNSQuery query
 */
int l_dnsquery_ref::l_DNSQuery(lua_State *l)
{
	const char *name;
	int type, _class;
	bool n = v_arg_string_opt(l, 1, "name", &name);
	bool t = v_arg_integer_opt(l, 1, "type", &type);
	bool c = v_arg_integer_opt(l, 1, "class", &_class);

	DNS::DNSQuery *q = l_dnsquery_ref::new_ref(l);
	if (n) q->SetName(name);
	if (t) q->SetType(type);
	if (c) q->SetClass(_class);

	return 1;
}

void l_dnsquery_ref::register_members(lua_State *l)
{
	l_ref<DNS::DNSQuery>::register_members(l);
	meta_bind_func(l, "new", l_DNSQuery);
	/***
	 * Get this object textual representation
	 * @function print
	 * @treturn string
	 */
	meta_bind_func(l, "print", l_print);
	/***
	 * see @{print}
	 * @function __tostring
	 */
	meta_bind_func(l, "__tostring", l_print);
}

/***
 * A DNS Answer
 * @type DNSAnswer
 */
int l_dnsanswer_ref::l_DNSAnswer(lua_State *l)
{
	(void)l;
	return 0;
}

void l_dnsanswer_ref::register_members(lua_State *l)
{
	l_ref<DNS::DNSAnswer>::register_members(l);
	meta_bind_func(l, "new", l_DNSAnswer);
	/***
	 * Get this object textual representation
	 * @function print
	 * @treturn string
	 */
	meta_bind_func(l, "print", l_print);
	/***
	 * see @{print}
	 * @function __tostring
	 */
	meta_bind_func(l, "__tostring", l_print);
}
