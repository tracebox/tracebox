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

#include "PartialHeader.h"

using namespace Crafter;
using namespace std;

void PartialTCP::DefineProtocol() {
	Fields.push_back(new ShortField("SrcPort",0,0));
	Fields.push_back(new ShortField("DstPort",0,2));
	Fields.push_back(new WordField("SeqNumber",1,0));
}

PartialTCP::PartialTCP(RawLayer& raw) {
	allocate_bytes(raw.GetSize());
	DefineProtocol();
	SetName("PartialTCP");
	SetprotoID(TCP::PROTO);
	PutData(raw.GetPayload().GetRawPointer());
}

void PartialTCP::Craft() { }

PartialTCP::~PartialTCP() { }

