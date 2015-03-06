#include "lua_ipv6segmentroutingheader.h"
#include "lua_arg.h"

using namespace Crafter;
using namespace std;

/* Assumes that the top of the stack is a table listing all segments */
int l_IPv6SegmentRoutingHeader_SetSegments_(
		IPv6SegmentRoutingHeader *srh, lua_State *l)
{
	/* Argument is a list of segments */
	luaL_checktype(l, -1, LUA_TTABLE);
	/* Iterate through the segment list */
	std::vector<IPv6SegmentRoutingHeader::segment_t> segments;
	for (int i = 1; ; ++i, lua_pop(l, 1)) {
		lua_rawgeti(l, -1, i);
		/* We reached the end */
		if (lua_isnil(l, -1)) {
			lua_pop(l, 1);
			break;
		}
		/* Segments are strings */
		const std::string ip = luaL_checklstring(l, -1, NULL);
		/* Representing an IPv6 address */
		IPv6SegmentRoutingHeader::segment_t s;
		if (s.ReadIPv6(ip) < 0) {
			const std::string msg = "Invalid IPv6 address: " + ip;
			return luaL_argerror(l, -1, msg.c_str());
		}
		segments.push_back(s);
	}
	/* Pop the segment list */
	lua_pop(l, 1);
	/* Replace the segment list in the srh */
	srh->Segments = segments;
	return 0;
}

int l_ipv6segmentroutingheader_ref::l_IPv6SegmentRoutingHeader_SetSegments(lua_State *l)
{
	IPv6SegmentRoutingHeader *srh = l_ipv6segmentroutingheader_ref::get(l, 1);
	l_IPv6SegmentRoutingHeader_SetSegments_(srh, l);
	/* We don't want to keep anything on the stack */
	return 0;
}

int l_IPv6SegmentRoutingHeader_SetPolicyList_(
		IPv6SegmentRoutingHeader *srh, lua_State *l)
{
	std::stringstream msg;
	/* Argument is a list of policies */
	luaL_checktype(l, -1, LUA_TTABLE);
	/* The number of policies is limited */
	const size_t policy_count = IPv6SegmentRoutingHeader::policy_list_t::GetSize();

	/* Iterate through the policies list */
	IPv6SegmentRoutingHeader::policy_list_t policies;
	IPv6SegmentRoutingHeader::policy_type_t policy_types[policy_count];
	for (size_t i = 0; i < policy_count; ++i)
		policy_types[i] = IPv6SegmentRoutingHeader::POLICY_UNSET;
	size_t idx;
	/* Will silently ignore policies if too many are specified */
	for (idx = 1; idx <= policy_count; ++idx, lua_pop(l, 1)) {
		lua_rawgeti(l, -1, idx);
		/* We reached the last element */
		if (lua_isnil(l, -1)) {
			/* Keep track of how many elements we read */
			--idx;
			lua_pop(l, 1);
			break;
		}
		/* Policies are table */
		if (!lua_istable(l, -1)) {
			msg << "Expected a table at index " << idx;
			return luaL_argerror(l, -1, msg.str().c_str());
		}

		/* Retrieve the policy type */
		lua_getfield(l, -1, "type");
		if (lua_isnil(l, -1)) {
			msg << "Missing policy type key at index " << idx;
			return luaL_argerror(l, -2, msg.str().c_str());
		}
		if (!lua_isnumber(l, -1)) {
			msg << "Policy type at index " << idx << " is not a number.";
			return luaL_argerror(l, -1, msg.str().c_str());
		}
		const int policy_type = lua_tointeger(l, -1);
		lua_pop(l, 1);
		/* Retrieve the policy value */
		lua_getfield(l, -1, "value");
		if (lua_isnil(l, -1)) {
			msg << "Missing policy value key at index " << idx;
			return luaL_argerror(l, -2, msg.str().c_str());
		}
		if (!lua_isstring(l, -1)) {
			msg << "Policy value at index " << idx << " is not a string";
			return luaL_argerror(l, -1, msg.str().c_str());

		}
		IPv6SegmentRoutingHeader::policy_t policy_val;
		if (policy_val.ReadIPv6(lua_tolstring(l, -1, NULL)) < 0) {
			msg << "Policy value at index " << idx << " is not an IPv6 address";
			return luaL_argerror(l, -1, msg.str().c_str());
		}
		lua_pop(l, 1);

		/* Store the policy */
		policies[idx-1] = policy_val;
		policy_types[idx-1] = (IPv6SegmentRoutingHeader::policy_type_t)policy_type;
	}

	/* Apply all policies, idx is <= policy_count */
	for (size_t i = 0; i < idx; ++i)
		srh->SetPolicy(i, policies[i], policy_types[i]);
	/* Pop the policy list */
	lua_pop(l, 1);
	return 0;
}

int l_ipv6segmentroutingheader_ref::l_IPv6SegmentRoutingHeader_SetPolicyList(lua_State *l)
{
	IPv6SegmentRoutingHeader *srh = l_ipv6segmentroutingheader_ref::get(l, 1);
	l_IPv6SegmentRoutingHeader_SetPolicyList_(srh, l);
	/* We don't want to keep anything on the stack */
	return 0;
}

int l_IPv6SegmentRoutingHeader_SetHMAC_(
		IPv6SegmentRoutingHeader *srh, lua_State *l)
{
	/* Argument is a list of bytes (small integers) */
	luaL_checktype(l, -1, LUA_TTABLE);
	/* Iterate through the integer list */
	IPv6SegmentRoutingHeader::hmac_t hmac;
	for (size_t i = 1; i <= hmac.GetSize(); ++i, lua_pop(l, 1)) {
		lua_rawgeti(l, -1, i);
		/* We reached the end */
		if (lua_isnil(l, -1)) {
			lua_pop(l, 1);
			break;
		}

		if (!lua_isnumber(l, -1)) {
			std::stringstream msg;
			msg << "Expected a byte value at index " << i;
			return luaL_argerror(l, -1, msg.str().c_str());
		}
		hmac[i-1] = lua_tointeger(l, -1);
	}

	srh->HMAC = hmac;
	/* Pop the hmac attributes */
	lua_pop(l, 1);
	return 0;
}

int l_ipv6segmentroutingheader_ref::l_IPv6SegmentRoutingHeader_SetHMAC(lua_State *l)
{
	IPv6SegmentRoutingHeader *srh = l_ipv6segmentroutingheader_ref::get(l, 1);
	l_IPv6SegmentRoutingHeader_SetHMAC_(srh, l);
	/* We don't want to keep anything on the stack */
	return 0;
}

int l_ipv6segmentroutingheader_ref::l_IPv6SegmentRoutingHeader(lua_State *l)
{
	IPv6SegmentRoutingHeader *srh;

	int segleft, hmackey;
	bool cflag, pflag;
	bool segleft_set = v_arg_integer_opt(l, 1, "segmentleft", &segleft);
	bool hmackey_set = v_arg_integer_opt(l, 1, "hmackey", &hmackey);
	bool cflag_set = v_arg_boolean_opt(l, 1, "cflag", &cflag);
	bool pflag_set = v_arg_boolean_opt(l, 1, "pflag", &pflag);

	srh = l_ipv6segmentroutingheader_ref::new_ref(l);
	if (!srh)
		return 0;

	if (segleft_set)
		srh->SetSegmentLeft(segleft);
	if (hmackey_set)
		srh->SetHMACKeyID(hmackey);
	if (cflag_set)
		srh->SetCFlag(cflag);
	if(pflag_set)
		srh->SetPFlag(pflag);

	if (v_arg(l, 1, "segments"))
		if (l_IPv6SegmentRoutingHeader_SetSegments_(srh, l) < 0)
			return 0;

	if (v_arg(l, 1, "hmac"))
		if (l_IPv6SegmentRoutingHeader_SetHMAC_(srh, l) < 0)
			return 0;

	if (v_arg(l, 1, "policies"))
		if (l_IPv6SegmentRoutingHeader_SetPolicyList_(srh, l) < 0)
			return 0;
	return 1;
}

static int set_segleft(lua_State *l)
{
	IPv6SegmentRoutingHeader *o = l_ipv6segmentroutingheader_ref::get(l, 1);
	o->SetSegmentLeft(l_data_type<byte>::get(l, 2));
	return 0;
}

void l_ipv6segmentroutingheader_ref::register_members(lua_State *l)
{
	l_layer_ref<IPv6SegmentRoutingHeader>::register_members(l);
	meta_bind_func(l, "segmentleft", set_segleft);
	meta_bind_func(l, "cflag", L_SETTER(word, IPv6SegmentRoutingHeader, CFlag));
	meta_bind_func(l, "pflag", L_SETTER(word, IPv6SegmentRoutingHeader, PFlag));
	meta_bind_func(l, "hmackey", L_SETTER(byte, IPv6SegmentRoutingHeader, HMACKeyID));
	meta_bind_func(l, "setsegments", l_IPv6SegmentRoutingHeader_SetSegments);
	meta_bind_func(l, "setpolicies", l_IPv6SegmentRoutingHeader_SetPolicyList);
	meta_bind_func(l, "sethmac", l_IPv6SegmentRoutingHeader_SetHMAC);
}

void l_ipv6segmentroutingheader_ref::register_globals(lua_State *l)
{
	l_layer_ref<IPv6SegmentRoutingHeader>::register_globals(l);
	lua_register(l, "srh", l_IPv6SegmentRoutingHeader);
	l_do(l, "function SRH(segs) return srh{segments=segs} end");
}
