/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __SNIFFER_H_
#define __SNIFFER_H_

#include <string>
#include "crafter/Packet.h"

/* A callback function that will be called for each received packet.
 * If it returns anything but 0, it will stop the sniffer. */
typedef int (*rcv_handler)(Crafter::Packet*, void*);

struct Sniffer_private;
class TbxSniffer {
	Sniffer_private *d;

	public:
	/* Create a Sniffer object,
	 * with the given key as iptable filter and callback fucntion*/
	TbxSniffer(const std::vector<const char*>&);
	~TbxSniffer();

	/* Start sniffing the network. Will call the rcv_handler for each new packet,
	 * with the given argument as last parameter */
	int start(rcv_handler, void*);
	/* Start sniffing the network. */
	int start();
	/* Retrieve a received packet, blocking if t is NULL */
	Crafter::Packet* recv(struct timespec *t);

	void stop();
};

#endif
