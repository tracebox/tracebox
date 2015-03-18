/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors. 
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "PacketModification.h"

using namespace std;

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

Deletion::Deletion(Layer *l) : Modification(l, l)
{
}

void Deletion::Print(std::ostream& out, bool verbose) const
{
	out << "-" << GetName();
	if (verbose)
		out << " " << field1_repr;
}

void PacketModifications::Print(std::ostream& out, bool verbose) const
{
	for(const_iterator it = begin() ; it != end() ; it++) {
		(*it)->Print(out, verbose);
		out << " ";
	}
}

PacketModifications::~PacketModifications()
{
	delete orig;

	for(const_iterator it = begin() ; it != end() ; it++)
		delete *it;

	clear();
}
