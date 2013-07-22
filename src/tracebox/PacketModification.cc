/*
 *  Copyright (C) 2013  Gregory Detal <gregory.detal@uclouvain.be>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

#include "PacketModification.h"

using namespace std;

Modification::Modification(int proto, std::string name, size_t offset, size_t len) :
							layer_proto(proto), name(name), offset(offset), len(len)
{
}

Modification::Modification(int proto, FieldInfo *info) : layer_proto(proto)
{
	Layer *l = Protocol::AccessFactory()->GetLayerByID(proto);
	offset = info->GetWord() * 32 + info->GetBit();
	len = info->GetLength();
	name += l->GetName() + "::" + info->GetName();
}

void Modification::Print(std::ostream& out) const
{
	out << name;
}

Addition::Addition(Layer *l) : Modification(l->GetID(), l->GetName(), 0, l->GetSize())
{
}

void Addition::Print(std::ostream& out) const
{
	out << "+" << GetName();
}

Deletion::Deletion(Layer *l) : Modification(l->GetID(), l->GetName(), 0, l->GetSize())
{
}

void Deletion::Print(std::ostream& out) const
{
	out << "-" << GetName();
}

void PacketModifications::Print(std::ostream& out) const
{
	for(const_iterator it = begin() ; it != end() ; it++) {
		(*it)->Print(out);
		out << " ";
	}
	out << endl;
}

static bool deleteAll(Modification *m)
{
	delete m;
	return true;
}

PacketModifications::~PacketModifications()
{
	delete orig;
	delete modif;

	for(const_iterator it = begin() ; it != end() ; it++)
		delete *it;

	clear();
}
