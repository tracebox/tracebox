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

#include "crafter.h"

using namespace Crafter;

class Modification {
	Packet *orig;
	Packet *modif;
	int proto;
	size_t offset;
	size_t len;
	std::string name;

public:
	Modification(int proto, std::string& name, size_t offset, size_t len);
	Modification(int proto, FieldInfo *info);

	void Print(std::ostream& out) const;
};

class PacketModifications : public std::vector<Modification> {
	Packet *orig;
	Packet *modif;

public:
	PacketModifications(Packet *orig, Packet *modif) : orig(orig), modif(modif) { }
	~PacketModifications() {
		delete orig;
		delete modif;
	}

	void Print(std::ostream& out) const;
};

