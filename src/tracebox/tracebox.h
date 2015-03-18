/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors. 
 *  Some rights reserved. See LICENSE, AUTHORS.
 */


#ifndef __TRACEBOX_H__
#define __TRACEBOX_H__

#include "crafter.h"
#include "PacketModification.h"

using namespace Crafter;

typedef int (tracebox_cb_t)(void *, int, std::string&, const Packet * const,
		Packet *, PacketModifications *);

IPLayer* probe_sanity_check(Packet *probe, std::string& err, std::string& iface);

int doTracebox(Packet *pkt, tracebox_cb_t *callback, std::string& err, void *ctx = NULL);

#endif
