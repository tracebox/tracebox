/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */
#include <algorithm>

#include "config.h"
#include "PacketModification.h"
#include "PartialHeader.h"

using namespace std;

static Layer *GetLayer(const Packet *pkt, int proto_id)
{
	for (Layer *l : *pkt) {
		if (l->GetID() == proto_id)
			return l;
	}
	return NULL;
}

static set<int> GetAllProtos(const Packet *p1, const Packet *p2)
{
	set<int> ret;

	for (Layer *l : *p1)
		ret.insert(l->GetID());
	for (Layer *l : *p2)
		ret.insert(l->GetID());

	/* Remove unwanted layers */
	ret.erase(Crafter::Ethernet::PROTO);
	ret.erase(Crafter::SLL::PROTO);
	ret.erase(Crafter::NullLoopback::PROTO);

	return ret;
}

static void ComputeDifferences(PacketModifications *modifs,
						const Layer *l1, const Layer *l2)
{
	byte* this_layer = new byte[l1->GetSize()];
	byte* that_layer = new byte[l1->GetSize()];

	/* Compute difference between fields */
	for(size_t i = 0 ; i < min(l1->GetFieldsSize(), l2->GetFieldsSize()) ; i++) {
		memset(this_layer, 0, l1->GetSize());
		memset(that_layer, 0, l1->GetSize());

		l1->GetField(i)->Write(this_layer);
		l2->GetField(i)->Write(that_layer);
		if (memcmp(this_layer, that_layer, l1->GetSize()))
			modifs->push_back(new Modification(l1->GetID(), l1->GetField(i), l2->GetField(i)));
	}

	/* TODO do something more clever here
	 * (ex: identify the offset where the change occured)
	 */
	if (l1->GetPayload().GetSize() < l2->GetPayload().GetSize())
		modifs->push_back(new Addition(l1));
	else if (l1->GetPayload().GetSize() > l2->GetPayload().GetSize())
		modifs->push_back(new Deletion(l1));
	else if (memcmp(l1->GetPayload().GetRawPointer(), l2->GetPayload().GetRawPointer(), l1->GetPayload().GetSize()))
		modifs->push_back(new Modification(l1, l2));

	delete[] this_layer;
	delete[] that_layer;
}

static PacketModifications* ComputeDifferences(
		std::shared_ptr<Packet> orig_shared, const Packet *modified,
		bool partial, std::vector<const Layer*> &extensions)
{

	PacketModifications *modifs = new PacketModifications(
			orig_shared, modified, extensions, partial);
	if (modified) {
		const Packet *orig = orig_shared.get();
		const set<int> protos = GetAllProtos(orig, modified);

		for (auto proto : protos) {
			const Layer *l1 = GetLayer(orig, proto);
			const Layer *l2 = GetLayer(modified, proto);

			if (l1 && l2)
				ComputeDifferences(modifs, l1, l2);
			else if (l1 && !l2 && !partial)
				modifs->push_back(new Deletion(l1));
			else if (!l1 && l2)
				modifs->push_back(new Addition(l2));
		}
	}
	return modifs;
}

Packet *TrimReply(Packet *rcv, bool *partial, size_t ip_total_len,
		int next_hdr, std::vector<const Layer*> &extensions)
{
	*partial = false;
	/* Remove any ICMP extension. */
	if (ip_total_len < rcv->GetSize()) {
		RawLayer *raw = GetRawLayer(*rcv);
		if (!raw)
			goto out;
		int len = raw->GetSize() - (rcv->GetSize() - ip_total_len);
		if (len > 0) {
			RawLayer new_raw(raw->GetPayload().GetRawPointer(), len);
			int remaining_len = raw->GetSize() - len;
			if (remaining_len > 0) {
				extensions.push_back(new RawLayer(
							raw->GetPayload().GetRawPointer() + len,
							remaining_len));
			}

			rcv->PopLayer();
			rcv->PushLayer(new_raw);
		}
	} else if (rcv->GetSize() < ip_total_len) {
		/* We have received a partial header */
		RawLayer *raw = GetRawLayer(*rcv);
		Layer *new_layer = NULL;

		if (!raw)
			goto out;

		switch(next_hdr) {
		case TCP::PROTO:
			new_layer = new PartialTCP(*raw);
			*partial = true;
			break;
		default:
			goto out;
		}
		if (new_layer) {
			rcv->PopLayer();
			rcv->PushLayer(new_layer);
		}
	}

out:
	return rcv;
}

Packet* TrimReplyIPv4(Packet *rcv, bool *partial,
		std::vector<const Layer*> &extensions)
{
	IP *ip = GetIP(*rcv);
	return TrimReply(rcv, partial, ip->GetTotalLength(), ip->GetProtocol(),
			extensions);
}

Packet* TrimReplyIPv6(Packet *rcv, bool *partial,
		std::vector<const Layer*> &extensions)
{
	IPv6 *ip = GetIPv6(*rcv);
	return TrimReply(rcv, partial, ip->GetPayloadLength() + 40,
			ip->GetNextHeader(), extensions);
}

static int find_layers_locations(Packet *rcv, int *proto, RawLayer **raw,
		std::vector<const Layer *> &extensions)
{
	if (!rcv)
		return -1;
	size_t layer_pos;
	int icmp_loc = 0;
	const Layer *layer;
	/* Find the IP Layer to know the version */
	for (layer_pos = 0; layer_pos < rcv->GetLayerCount()
			&& *proto != IP::PROTO
			&& *proto != IPv6::PROTO; ++layer_pos) {
		layer = (*rcv)[layer_pos];
		*proto = layer->GetID();
	}
	if (layer_pos >= rcv->GetLayerCount())
		/* No IP layer */
		return -1;
	layer = (*rcv)[layer_pos];
	if (layer->GetID() != ICMP::PROTO && layer->GetID() != ICMPv6::PROTO)
		/* No ICMP Layer */
		return -1;
	/* Register the ICMP Layer location */
	icmp_loc = layer_pos++;
	/* Find the Raw Layer itself and register its location as it contains
	 * the echoed packet */
	if (layer_pos >= rcv->GetLayerCount() ||
			!(*raw = rcv->GetLayer<RawLayer>(layer_pos++)))
		/* No raw layer, i.e. incorrect ICMP reply for our use case */
		return -1;
	/* Keep track of any ICMP extension */
	for (; layer_pos < rcv->GetLayerCount(); ++layer_pos) {
		Layer *layer = (*rcv)[layer_pos];
		Layer *new_layer = Protocol::AccessFactory()->GetLayerByID(layer->GetID());
		*new_layer = *layer;
		extensions.push_back(new_layer);
	}
	return icmp_loc;
}

PacketModifications* PacketModifications::ComputeModifications(
		std::shared_ptr<Crafter::Packet> pkt, Crafter::Packet *rcv)
{
	bool partial = false;
	std::vector<const Layer*> extensions;
	int proto, icmp_loc;
	RawLayer *raw;
	/* It should normally be impossible to have an ICMP Layer at index 0 as it
	 * would indicate that we received it without an encapsulating IP header
	 * which is impossible unless the user explicitely crafts (incorrect)
	 * responses */
	icmp_loc = find_layers_locations(rcv, &proto, &raw, extensions);
	if (icmp_loc > 0) {
		/* If there are ICMP extensions, then the raw-sandwich layer might
		 * include padding ... */
		int len_without_padding = raw->GetSize();
		Packet *cnt = new Packet(rcv->GetTimestamp());
		switch (proto) {
		case IP::PROTO: {
			ICMP *icmp = rcv->GetLayer<ICMP>(icmp_loc);
			if (icmp->GetLength())
				len_without_padding = std::min(len_without_padding,
						icmp->GetLength() * 4);
			cnt->PacketFromIP(raw->GetRawPointer(),
					len_without_padding);
			/* We might receive an ICMP without the complete
			 * echoed packet or with ICMP extensions. We thus
			 * remove undesired parts and parse partial headers.
			 */
			cnt = TrimReplyIPv4(cnt, &partial, extensions);
			break;
		}
		case IPv6::PROTO: {
			ICMPv6 *icmp = rcv->GetLayer<ICMPv6>(icmp_loc);
			if (icmp->GetLength())
				len_without_padding = std::min(len_without_padding,
						icmp->GetLength() * 8);
			cnt->PacketFromIPv6(raw->GetRawPointer(),
					len_without_padding);
			cnt = TrimReplyIPv6(cnt, &partial, extensions);
			break;
		}
		default:
			delete cnt;
			cnt = NULL;
		}

		delete rcv;
		rcv = cnt;
	}
	return ComputeDifferences(pkt, rcv, partial, extensions);
}

Modification::Modification(int proto, std::string name, size_t offset,
		size_t len) : layer_proto(proto), name(name), offset(offset), len(len)
{
}

Modification::Modification(int proto, const FieldInfo *f1,
		const FieldInfo *f2) : layer_proto(proto)
{
	Layer *l = Protocol::AccessFactory()->GetLayerByID(proto);
	std::ostringstream sf1, sf2;

	offset = f1->GetWord() * 32 + f1->GetBit();
	len = f1->GetLength();
	name += l->GetName() + "::" + f1->GetName();

	f1->PrintValue(sf1);
	field1_repr = sf1.str();

	f2->PrintValue(sf2);
	field2_repr = sf2.str();
}

Modification::Modification(const Layer *l1, const Layer *l2) :
	layer_proto(l1->GetID()), name(l1->GetName()),
	offset(0), len(l1->GetSize())
{
	std::ostringstream sf1, sf2;

	l1->Print(sf1);
	field1_repr = sf1.str();

	l2->Print(sf2);
	field2_repr = sf2.str();
}

void Modification::Print(std::ostream& out, bool verbose) const
{
	out << name;
	if (verbose)
		out << GetModifRepr();
}

void Modification::Print_JSON(json_object *res, json_object *add,
		json_object *del, bool verbose) const
{
	if (verbose)
	{
			json_object *modif = GetModifRepr_JSON();
			json_object *modif_header = json_object_new_object();
			json_object_object_add(modif_header,name.c_str(), modif);
			json_object_array_add(res,modif_header);

	}
	else
	{
		json_object_array_add(res, json_object_new_string(name.c_str()));
	}
}

json_object* Modification::GetModifRepr_JSON() const
{
	json_object *modif = json_object_new_object();
	if (field1_repr != "" && field2_repr != ""){
		json_object_object_add(modif, "Expected",
				json_object_new_string(field1_repr.c_str()));
		json_object_object_add(modif, "Received",
				json_object_new_string(field2_repr.c_str()));
	}
	return modif;
}

std::string Modification::GetModifRepr() const
{
	if (field1_repr != "" && field2_repr != "")
		return " (" + field1_repr + " -> " + field2_repr + ")";
	return "";
}

Addition::Addition(const Layer *l) : Modification(l, l)
{
}

void Addition::Print(std::ostream& out, bool verbose) const
{
	out << "+" << GetName();
	if (verbose)
		out << " " << field1_repr;
}

void Addition::Print_JSON(json_object *res, json_object *add,
		json_object *del, bool verbose) const
{
	if (verbose)
	{
			json_object *modif = json_object_new_object();

			json_object_object_add(modif,"Info",
					json_object_new_string(field1_repr.c_str()));

			json_object *modif_header = json_object_new_object();
			json_object_object_add(modif_header,GetName().c_str(), modif);
			json_object_array_add(add,modif_header);

	}
	else
	{
		json_object_array_add(add, json_object_new_string(GetName().c_str()));
	}
}

Deletion::Deletion(const Layer *l) : Modification(l, l)
{
}

void Deletion::Print(std::ostream& out, bool verbose) const
{
	out << "-" << GetName();
	if (verbose)
		out << " " << field1_repr;
}

void Deletion::Print_JSON(json_object *res, json_object *add,
		json_object *del, bool verbose) const
{
	if (verbose)
	{
			json_object *modif = json_object_new_object();

			json_object_object_add(modif,"Info",
					json_object_new_string(field1_repr.c_str()));

			json_object *modif_header = json_object_new_object();
			json_object_object_add(modif_header,GetName().c_str(), modif);
			json_object_array_add(del,modif_header);

	}
	else
	{
		json_object_array_add(del, json_object_new_string(GetName().c_str()));
	}
}

void PacketModifications::Print(std::ostream& out, bool verbose) const
{
	if (partial)
		out << " [PARTIAL] ";
	for(const_iterator it = begin() ; it != end() ; it++) {
		(*it)->Print(out, verbose);
		out << " ";
	}
	if (extensions.size() > 0) {
		out << "[Extra headers: ";
		for (std::vector<const Layer *>::const_iterator it = extensions.begin();
				it != extensions.end();	++it) {
			if (verbose) {
				(*it)->Print(out);
				out << " ";
			} else out << (*it)->GetName() << " ";
		}
		out << "] ";
	}
}

void PacketModifications::Print_JSON(json_object *res,
		json_object *add, json_object *del, json_object **ext,
		bool verbose) const
{
	for(const_iterator it = begin() ; it != end() ; ++it)
		(*it)->Print_JSON(res, add, del, verbose);
	if (extensions.size() > 0) {
		*ext = json_object_new_array();
		for (std::vector<const Layer *>::const_iterator it = extensions.begin();
				it != extensions.end();	++it) {
			if (verbose) {
				std::ostringstream ss;
				(*it)->Print(ss);
				std::string str = ss.str();
				str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());

				json_object *descr = json_object_new_object();
				json_object_object_add(descr, "Info",
						json_object_new_string(str.c_str()));

				json_object *descr_hdr = json_object_new_object();
				json_object_object_add(descr_hdr, (*it)->GetName().c_str(),
						descr);
				json_object_array_add(*ext, descr_hdr);
			} else {
				json_object_array_add(*ext, json_object_new_string(
							(*it)->GetName().c_str()));
			}
		}
	}
}

PacketModifications::~PacketModifications()
{
	for (std::vector<const Layer *>::const_iterator it = extensions.begin();
			it != extensions.end(); ++it)
		delete *it;
	for(const_iterator it = begin() ; it != end() ; ++it)
		delete *it;
	clear();
}
