/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "config.h"
#include "PacketModification.h"
#include "PartialHeader.h"

using namespace std;

static Layer *GetLayer(Packet *pkt, int proto_id)
{
	for (Layer *l : *pkt) {
		if (l->GetID() == proto_id)
			return l;
	}
	return NULL;
}

static set<int> GetAllProtos(Packet *p1, Packet *p2)
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
						Layer *l1, Layer *l2)
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

static PacketModifications* ComputeDifferences(Packet *orig, Packet *modified, bool partial)
{
	PacketModifications *modifs = new PacketModifications(orig, modified, partial);
	set<int> protos = GetAllProtos(orig, modified);

	for (auto proto : protos) {
		Layer *l1 = GetLayer(orig, proto);
		Layer *l2 = GetLayer(modified, proto);

		if (l1 && l2)
			ComputeDifferences(modifs, l1, l2);
		else if (l1 && !l2 && !partial)
			modifs->push_back(new Deletion(l1));
		else if (!l1 && l2)
			modifs->push_back(new Addition(l2));
	}

	return modifs;
}

Packet* TrimReplyIPv4(Packet *rcv, bool *partial)
{
	IP *ip = GetIP(*rcv);

	*partial = false;
	/* Remove any ICMP extension. */
	if (ip->GetTotalLength() < rcv->GetSize()) {
		RawLayer *raw = GetRawLayer(*rcv);
		int len = raw->GetSize() - (rcv->GetSize() - ip->GetTotalLength());
		RawLayer new_raw(raw->GetPayload().GetRawPointer(), len);

		rcv->PopLayer();
		if (len)
			rcv->PushLayer(new_raw);
	} else if (rcv->GetSize() < ip->GetTotalLength()) {
		/* We have received a partial header */
		RawLayer *raw = GetRawLayer(*rcv);
		Layer *new_layer = NULL;

		if (!raw)
			return rcv;

		switch(ip->GetProtocol()) {
		case TCP::PROTO:
			new_layer = new PartialTCP(*raw);
			*partial = true;
			break;
		default:
			return rcv;
		}
		if (new_layer) {
			rcv->PopLayer();
			rcv->PushLayer(new_layer);
		}
	}

	return rcv;
}

Packet* TrimReplyIPv6(Packet *rcv, bool *partial)
{
	IPv6 *ip = GetIPv6(*rcv);

	*partial = false;
	/* Remove any extension. */
	if ((size_t)ip->GetPayloadLength() + 40 < rcv->GetSize()) {
		RawLayer *raw = GetRawLayer(*rcv);
		int len = raw->GetSize() - (rcv->GetSize() - (ip->GetPayloadLength() + 40));
		RawLayer new_raw(raw->GetPayload().GetRawPointer(), len);

		rcv->PopLayer();
		if (len)
			rcv->PushLayer(new_raw);
	} else if (rcv->GetSize() < (size_t)ip->GetPayloadLength() + 40) {
		/* We have received a partial header */
		RawLayer *raw = GetRawLayer(*rcv);
		Layer *new_layer = NULL;

		if (!raw)
			return rcv;

		switch(ip->GetNextHeader()) {
		case TCP::PROTO:
			new_layer = new PartialTCP(*raw);
			*partial = true;
			break;
		default:
			return rcv;
		}
		if (new_layer) {
			rcv->PopLayer();
			rcv->PushLayer(new_layer);
		}
	}

	return rcv;
}

PacketModifications* PacketModifications::ComputeModifications(Crafter::Packet *pkt,
			Crafter::Packet **rcv)
{
	ICMPLayer *icmp = (*rcv)->GetLayer<ICMPLayer>();
	RawLayer *raw = (*rcv)->GetLayer<RawLayer>();
	bool partial = false;
	int proto = pkt->GetLayer<IPLayer>()->GetID();

	if (icmp && raw) {
		Packet *cnt = new Packet;
		switch (proto) {
		case IP::PROTO:
			cnt->PacketFromIP(*raw);
			/* We might receive an ICMP without the complete
			 * echoed packet or with ICMP extensions. We thus
			 * remove undesired parts and parse partial headers.
			 */
			cnt = TrimReplyIPv4(cnt, &partial);
			break;
		case IPv6::PROTO:
			cnt->PacketFromIPv6(*raw);
			cnt = TrimReplyIPv6(cnt, &partial);
			break;
		default:
			delete cnt;
			return NULL;
		}

		delete *rcv;
		*rcv = cnt;
	}

	return ComputeDifferences(pkt, *rcv, partial);
}

Modification::Modification(int proto, std::string name, size_t offset, size_t len) :
	layer_proto(proto), name(name), offset(offset), len(len)
{
}

Modification::Modification(int proto, FieldInfo *f1, FieldInfo *f2) : layer_proto(proto)
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

Modification::Modification(Layer *l1, Layer *l2) : layer_proto(l1->GetID()), name(l1->GetName()),
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

void Modification::Print_JSON(json_object *res, json_object *add, json_object *del, bool verbose) const
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
		json_object_object_add(modif,"Expected", json_object_new_string(field1_repr.c_str()));
		json_object_object_add(modif,"Received", json_object_new_string(field2_repr.c_str()));
	}
	return modif;
}

std::string Modification::GetModifRepr() const
{
	if (field1_repr != "" && field2_repr != "")
		return " (" + field1_repr + " -> " + field2_repr + ")";
	return "";
}

Addition::Addition(Layer *l) : Modification(l, l)
{
}

void Addition::Print(std::ostream& out, bool verbose) const
{
	out << "+" << GetName();
	if (verbose)
		out << " " << field1_repr;
}

void Addition::Print_JSON(json_object *res, json_object *add, json_object *del, bool verbose) const
{
	if (verbose)
	{
			json_object *modif = json_object_new_object();

			json_object_object_add(modif,"Info", json_object_new_string(field1_repr.c_str()));

			json_object *modif_header = json_object_new_object();
			json_object_object_add(modif_header,GetName().c_str(), modif);
			json_object_array_add(add,modif_header);

	}
	else
	{
		json_object_array_add(add, json_object_new_string(GetName().c_str()));
	}
}

Deletion::Deletion(Layer *l) : Modification(l, l)
{
}

void Deletion::Print(std::ostream& out, bool verbose) const
{
	out << "-" << GetName();
	if (verbose)
		out << " " << field1_repr;
}

void Deletion::Print_JSON(json_object *res, json_object *add, json_object *del, bool verbose) const
{
	if (verbose)
	{
			json_object *modif = json_object_new_object();

			json_object_object_add(modif,"Info", json_object_new_string(field1_repr.c_str()));

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
}

void PacketModifications::Print_JSON(json_object *res,json_object *icmp, json_object *add, json_object *del, bool verbose) const
{
	for(const_iterator it = begin() ; it != end() ; it++) {
		(*it)->Print_JSON(res, add, del, verbose);
	}
}

PacketModifications::~PacketModifications()
{
	delete orig;

	for(const_iterator it = begin() ; it != end() ; it++)
		delete *it;

	clear();
}
