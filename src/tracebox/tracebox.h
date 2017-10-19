/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */


#ifndef __TRACEBOX_H__
#define __TRACEBOX_H__

#include <memory>

#include "crafter.h"
#include "config.h"
#include "PacketModification.h"

extern double tbx_default_timeout;
extern bool print_debug;

typedef int (tracebox_cb_t)(void *, uint8_t, std::string&, PacketModifications *);

IPLayer* probe_sanity_check(const Crafter::Packet *probe,
		std::string& err, std::string& iface);

int doTracebox(std::shared_ptr<Crafter::Packet> pkt, tracebox_cb_t *callback,
		std::string& err, void *ctx = NULL);

int set_tracebox_ttl_range(uint8_t ttl_min, uint8_t ttl_max);
uint8_t get_min_ttl();
uint8_t get_max_ttl();

void writePcap(Packet* p);

#ifdef HAVE_CURL
void curlPost(const char *pcap_filename, const char *url);
#endif

#endif
