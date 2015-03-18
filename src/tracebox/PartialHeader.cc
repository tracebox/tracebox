/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors. 
 *  Some rights reserved. See LICENSE, AUTHORS.
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

