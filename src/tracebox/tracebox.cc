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
#include "crafter/Utils/IPResolver.h"
#include "script.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" {
#include <pcap/pcap.h>
};

using namespace Crafter;
using namespace std;

Packet *BuildProbe(int dport)
{
	Packet *pkt = new Packet();
	IP ip = IP();
	TCP tcp = TCP();

	tcp.SetDstPort(dport);
	tcp.SetFlags(0x1);

	pkt->PushLayer(ip);
	pkt->PushLayer(tcp);

	pkt->PreCraft();

	return pkt;
}

string resolve_name(int proto, string& name)
{
	switch (proto) {
	case IP::PROTO:
		return GetIP(name);
	case IPv6::PROTO:
		return GetIPv6(name);
	default:
		return "";
	}
}

string iface_address(int proto, string& iface)
{
	switch (proto) {
	case IP::PROTO:
		return GetMyIP(iface);
	case IPv6::PROTO:
		return GetMyIPv6(iface, false);
	default:
		return "";
	}
}

void SendProbe(int proto, const string& iface, Packet *pkt,
	       const string& sourceIP, const string& destinationIP,
	       const string& destination, int hop_max, bool resolve)
{
	int ttl;

	cout << "tracebox to " << destinationIP << " (" << destination << "): " << hop_max << " hops max" << endl;
	for (ttl = 1; ttl <= hop_max; ++ttl) {
		IPLayer *ip = pkt->GetLayer<IPLayer>();
		ip->SetSourceIP(sourceIP);
		ip->SetDestinationIP(destinationIP);

		switch (proto) {
		case IP::PROTO:
			reinterpret_cast<IP *>(ip)->SetTTL(ttl);
		case IPv6::PROTO:
			reinterpret_cast<IPv6 *>(ip)->SetHopLimit(ttl);
		}
		pkt->PreCraft();
		pkt->Print(cout);

		Packet* rcv = pkt->SendRecv(iface, 1, 3);
		if (rcv) {
			ip = rcv->GetLayer<IP>();
			if (!resolve)
				cout << ttl << ": " << ip->GetSourceIP() << endl;
			else
				cout << ttl << ": " << GetHostname(ip->GetSourceIP()) << " (" << ip->GetSourceIP() << ")" << endl;
		} else
			cout << ttl << ": *" << endl;

		/* Stop if we reached the destination */
		if (ip->GetSourceIP() == destinationIP)
			return;
	}
}

int main(int argc, char *argv[])
{
	char c;
	string iface, destination;
	string sourceIP, destinationIP;
	int hops_max = 64;
	bool resolve = true;
	const char *script = NULL;
	const char *probe = NULL;
	Packet *pkt = NULL;
	IPLayer *ip = NULL;

	while ((c = getopt(argc, argv, ":i:m:s:p:hn")) != -1) {
		switch (c) {
			case 'i':
				iface = optarg;
				break;
			case 'm':
				hops_max = strtol(optarg, NULL, 10);
				break;
			case 'n':
				resolve = false;
				break;
			case 's':
				script = optarg;
				break;
			case 'p':
				probe = optarg;
				break;
			case 'h':
				goto usage;
			case ':':
				cerr << "missing option argument" << endl;
			default:
				goto usage;
		}
	}

	if (iface == "") {
		cerr << "You need to specify an interface" << endl;
		goto usage;
	}

	if (!probe && !script) {
		pkt = BuildProbe(80);
	} else if (probe && !script) {
		string cmd = probe;
		pkt = script_packet(cmd);
	} else if (script && !probe) {
		string f = script;
		script_execfile(f);
		goto out;
	} else {
		cerr << "You cannot specify a script and a probe at the same time" << endl;
		goto usage;
	}

	if (!pkt)
		goto out;

	// is IPv4 or IPv6 ???
	ip = pkt->GetLayer<IPLayer>();
	if (!ip) {
		cout << "You need to specify at least an IPv4 or IPv6 header" << endl;
		goto out;
	}

	destinationIP = destination = ip->GetDestinationIP();
	if (destinationIP == "0.0.0.0" || destinationIP == "::") {
		destination = argv[argc-1];
		destinationIP = resolve_name(ip->GetID(), destination);
	}

	if (destinationIP == "") {
		cout << "You need to specify a destination" << endl;
		goto out;
	}

	sourceIP = iface_address(ip->GetID(), iface);
	if (sourceIP == "") {
		cout << "There is no source address for the specified protocol" << endl;
		goto out;
	}

	SendProbe(ip->GetID(), iface, pkt, sourceIP, destinationIP, destination, hops_max, resolve);

out:
	return 0;

usage:
	fprintf(stderr, "Usage:\n"
"  %s [ -hn ] [ OPTIONS ] host\n"
"Options are:\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -i device                   Specify a network interface to operate with\n"
"  -m hops_max                 Set the max number of hops (max TTL to be\n"
"                              reached). Default is 30\n"
"  -p probe                    Specify the probe to send.\n"
"  -s script                   Run a script.\n"
"", argv[0]);
	exit(EXIT_FAILURE);
}
