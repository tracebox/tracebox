/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */


#ifndef __TRACEBOX_H__
#define __TRACEBOX_H__

#include "crafter.h"
#include "config.h"
#include "PacketModification.h"

extern double tbx_default_timeout;

typedef int (tracebox_cb_t)(void *, int, std::string&,
		const Crafter::Packet * const,
		Crafter::Packet *, PacketModifications *);

IPLayer* probe_sanity_check(Crafter::Packet *probe,
		std::string& err, std::string& iface);

int doTracebox(Crafter::Packet *pkt, tracebox_cb_t *callback,
		std::string& err, void *ctx = NULL);

void writePcap(Packet* p);

#ifdef HAVE_CURL
void curlPost(const char *pcap_filename, const char *url);
#endif

#endif
