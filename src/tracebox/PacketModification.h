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

#ifndef __PACKETMODIFICATION_H__
#define __PACKETMODIFICATION_H__

#include "crafter.h"

using namespace Crafter;

class Modification {
	/* Layer protocol where the modification occured. The protocol is as defined
	 * in Libcrafter.
	 */
	int layer_proto;

	/* Representation of the modification */
	std::string name;

	/* Offset compared to the start of the layer (in bits) */
	size_t offset;

	/* Length of the modification (in bits) */
	size_t len;

	/* Some private functions */
	std::string GetModifRepr() const;

protected:
	/* Field values helper */
	std::string field1_repr;
	std::string field2_repr;


public:
	Modification(int proto, std::string name, size_t offset, size_t len);
	Modification(int proto, FieldInfo *f1, FieldInfo *f2);
	Modification(Layer *l1, Layer *l2);

	int getOffset() const {
		return offset;
	}

	int GetOffsetBytes() const {
		return offset / 32;
	}

	size_t GetLength() const {
		return len;
	}

	std::string GetName() const {
		return name;
	}

	virtual ~Modification() {}

	virtual void Print(std::ostream& out = std::cout, bool verbose = false) const;
};

class Addition : public Modification {
public:
	Addition(Layer *l);

	virtual void Print(std::ostream& out, bool verbose = false) const;
};

class Deletion : public Modification {
public:
	Deletion(Layer *l);

	virtual void Print(std::ostream& out, bool verbose = false) const;
};

class PacketModifications : public std::vector<Modification *> {
	Packet *orig;
	Packet *modif;

public:
	PacketModifications(Packet *orig, Packet *modif) : orig(new Packet(*orig)), modif(modif) { }
	~PacketModifications();

	void Print(std::ostream& out = std::cout, bool verbose = false) const;
};

#endif
