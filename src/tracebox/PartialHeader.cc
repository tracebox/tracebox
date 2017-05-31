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
	SetName("PartialTCP");
	SetprotoID(PROTO);
}

PartialTCP::PartialTCP() {
	allocate_bytes(8);
	PartialTCP::DefineProtocol();
	SetSrcPort(0);
	SetDstPort(0);
	SetSeqNumber(0);
}

PartialTCP::PartialTCP(RawLayer& raw) {
	allocate_bytes(raw.GetSize());
	PartialTCP::DefineProtocol();
	PutData(raw.GetPayload().GetRawPointer());
}

PartialTCP::PartialTCP(PartialTCP &partial) {
	allocate_bytes(partial.GetSize());
	PartialTCP::DefineProtocol();
	PutData(partial.GetRawPointer());
}

string PartialTCP::MatchFilter() const {
	char src_port[6];
	char dst_port[6];
	sprintf(src_port,"%d", GetSrcPort());
	sprintf(dst_port,"%d", GetDstPort());
	std::string ret_str = "tcp and dst port " + std::string(src_port) +
		" and src port " + std::string(dst_port);
	return ret_str;
}

void PartialTCP::register_type() {
	PartialTCP dummy;
	Protocol::AccessFactory()->Register(&dummy);
}
