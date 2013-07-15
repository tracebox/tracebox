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
#include "PartialHeader.h"
#include "PacketModification.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" {
#include <pcap/pcap.h>
#include <ifaddrs.h>
};

using namespace Crafter;
using namespace std;

template<int n> void BuildNetworkLayer(Packet *) { }
template<int n> void BuildTransportLayer(Packet *, int) { }

template<>
void BuildNetworkLayer<IP::PROTO>(Packet *pkt)
{
	IP ip = IP();
#ifdef __APPLE__
	ip.SetIdentification(rand());
#endif
	pkt->PushLayer(ip);
}

template<>
void BuildNetworkLayer<IPv6::PROTO>(Packet *pkt)
{
	pkt->PushLayer(IPv6());
}

template<>
void BuildTransportLayer<TCP::PROTO>(Packet *pkt, int dport)
{
	TCP tcp = TCP();
	tcp.SetSrcPort(rand());
	tcp.SetDstPort(dport);
	tcp.SetSeqNumber(rand());
	tcp.SetFlags(0x2);
	pkt->PushLayer(tcp);
}

template<>
void BuildTransportLayer<UDP::PROTO>(Packet *pkt, int dport)
{
	UDP udp = UDP();
	udp.SetSrcPort(rand());
	udp.SetDstPort(dport);
	pkt->PushLayer(udp);
}

Packet *BuildProbe(int net, int tr, int dport)
{
	Packet *pkt = new Packet();
	switch(net) {
	case IP::PROTO:
		BuildNetworkLayer<IP::PROTO>(pkt);
		break;
	case IPv6::PROTO:
		BuildNetworkLayer<IPv6::PROTO>(pkt);
		break;
	}
	switch(tr) {
	case TCP::PROTO:
		BuildTransportLayer<TCP::PROTO>(pkt, dport);
		break;
	case UDP::PROTO:
		BuildTransportLayer<UDP::PROTO>(pkt, dport);
		break;
	}
	return pkt;
}

string GetDefaultIface(bool ipv6)
{
	struct sockaddr_storage sa;
	int i, fd, af = ipv6 ? AF_INET6 : AF_INET;
	socklen_t n;
	size_t sa_len;
	struct ifaddrs *ifaces, *ifa;

	memset(&sa, 0, sizeof(sa));
	if (ipv6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
		sin6->sin6_family = af;
		sa_len = sizeof(*sin6);
		inet_pton(af, "2001:6a8:3080:2:94b0:b600:965:8cf5", &sin6->sin6_addr);
		sin6->sin6_port = htons(666);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
		sin->sin_family = af;
		sa_len = sizeof(*sin);
		inet_pton(af, "130.104.230.45", &sin->sin_addr);
		sin->sin_port = htons(666);
	}

	if ((fd = socket(af, SOCK_DGRAM, 0)) < 0)
		goto out;
	if (connect(fd, (struct sockaddr *)&sa, sa_len) < 0) {
		perror("connect");
		goto error;
	}

	n = sa_len;
	if (getsockname(fd, (struct sockaddr *)&sa, &n) < 0)
		goto error;

	if (getifaddrs(&ifaces) < 0)
		goto error;

	for (ifa = ifaces; ifa != 0; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == af) {
			void *ifa_addr, *saddr;
			size_t len = ipv6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
			ifa_addr = ipv6 ? (void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr :
					(void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			saddr = ipv6 ? (void *)&((struct sockaddr_in6 *)&sa)->sin6_addr :
					(void *)&((struct sockaddr_in *)&sa)->sin_addr;
			if (!memcmp(ifa_addr, saddr, len)) {
				freeifaddrs(ifaces);
				close(fd);
				return ifa->ifa_name;
			}
		}
	}

	freeifaddrs(ifaces);
error:
	close(fd);
out:
	return "";
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

Layer *GetLayer(Packet *pkt, int proto_id)
{
	LayerStack::const_iterator it;

	for (it = pkt->begin() ; it != pkt->end() ; it++) {
		Layer *l = *it;
		if (l->GetID() == proto_id)
			return l;
	}
	return NULL;
}

set<int> GetAllProtos(Packet *p1, Packet *p2)
{
	set<int> ret;
	LayerStack::const_iterator it;

	for (it = p1->begin() ; it != p1->end() ; it++)
		ret.insert((*it)->GetID());
	for (it = p2->begin() ; it != p2->end() ; it++)
		ret.insert((*it)->GetID());
	return ret;
}

void ComputeDifferences(PacketModifications *modifs,
						Layer *l1, Layer *l2)
{
	byte* this_layer = new byte[l1->GetSize()];
	byte* that_layer = new byte[l1->GetSize()];

	/* Compute difference between fields */
	for(size_t i = 0 ; i < min(l1->GetFieldsSize(), l2->GetFieldsSize()) ; i++) {
		memset(this_layer, 0, l1->GetSize());
		memset(that_layer, 0, l1->GetSize());

		l1->GetField(i)->Write(this_layer);
		l2->GetField(i)->Write(that_layer);
		if (memcmp(this_layer, that_layer, l1->GetSize()))
			modifs->push_back(Modification(l1->GetID(), l1->GetField(i)));
	}

	if (l1->GetPayload().GetSize() != l2->GetPayload().GetSize())
		std::cout << l2->GetName() << "->" << "Payload has changed" << std::endl;
	else if (memcmp(l1->GetPayload().GetRawPointer(), l2->GetPayload().GetRawPointer(), l1->GetPayload().GetSize()))
		std::cout << l2->GetName() << "->" << "Payload has changed" << std::endl;

	delete[] this_layer;
	delete[] that_layer;
}

PacketModifications* ComputeDifferences(Packet *orig, Packet *modified, bool partial)
{
	PacketModifications *modifs = new PacketModifications(orig, modified);
	set<int> protos = GetAllProtos(orig, modified);
	set<int>::iterator it = protos.begin();

	for ( ; it != protos.end() ; it++) {
		Layer *l1 = GetLayer(orig, *it);
		Layer *l2 = GetLayer(modified, *it);

		if (l1 && l2)
			ComputeDifferences(modifs, l1, l2);
		else if (l1 && !l2 && !partial)
			cout << l1->GetName() << " was suppressed" << endl;
		else if (!l1 && l2)
			cout << l2->GetName() << " was added" << endl;
	}

	return modifs;
}

Packet* TrimReplyIPv4(Packet *pkt, Packet *rcv, bool *partial)
{
	IP *ip = GetIP(*rcv);

	*partial = false;
	/* Remove any ICMP extension. */
	if (ip->GetTotalLength() < rcv->GetSize()) {
		RawLayer *raw = GetRawLayer(*rcv);
		int len = raw->GetSize() - (rcv->GetSize() - ip->GetTotalLength());
		RawLayer new_raw(raw->GetPayload().GetRawPointer(), len);

		rcv->PopLayer();
		if (len)
			rcv->PushLayer(new_raw);
	} else if (rcv->GetSize() < ip->GetTotalLength()) {
		/* We have received a partial header */
		RawLayer *raw = GetRawLayer(*rcv);
		Layer *new_layer = NULL;

		if (!raw)
			return rcv;

		switch(ip->GetProtocol()) {
		case TCP::PROTO:
			new_layer = new PartialTCP(*raw);
			*partial = true;
			break;
		default:
			return rcv;
		}
		if (new_layer) {
			rcv->PopLayer();
			rcv->PushLayer(new_layer);
		}
	}

	return rcv;
}

Packet* TrimReplyIPv6(Packet *pkt, Packet *rcv)
{
	IPv6 *ip = GetIPv6(*rcv);

	/* Remove any extension. */
	if (ip->GetPayloadLength() + 40 < rcv->GetSize()) {
		RawLayer *raw = GetRawLayer(*rcv);
		int len = raw->GetSize() - (rcv->GetSize() - (ip->GetPayloadLength() + 40));
		RawLayer new_raw(raw->GetPayload().GetRawPointer(), len);

		rcv->PopLayer();
		if (len)
			rcv->PushLayer(new_raw);
	}

	return rcv;
}

PacketModifications* RecvReply(int proto, Packet *pkt, Packet *rcv)
{
	ICMPLayer *icmp = rcv->GetLayer<ICMPLayer>();
	RawLayer *raw = rcv->GetLayer<RawLayer>();
	Packet *cnt;
	bool partial = false;

	if (!icmp || !raw)
		return NULL;

	cnt = new Packet;
	switch (proto) {
	case IP::PROTO:
		cnt->PacketFromIP(*raw);
		/* We might receive an ICMP without the complete
		 * echoed packet or with ICMP extensions. We thus
		 * remove undesired parts and parse partial headers.
		 */
		cnt = TrimReplyIPv4(pkt, cnt, &partial);
		break;
	case IPv6::PROTO:
		cnt->PacketFromIPv6(*raw);
		cnt = TrimReplyIPv6(pkt, cnt);
		break;
	default:
		return NULL;
	}

	return ComputeDifferences(pkt, cnt, partial);
}

void SendProbe(int proto, const string& iface, Packet *pkt,
	       const string& sourceIP, const string& destinationIP,
	       const string& destination, int hop_max, bool resolve)
{
	int ttl;

	cout << "tracebox to " << destinationIP << " (" << destination << "): " << hop_max << " hops max" << endl;
	for (ttl = 1; ttl <= hop_max; ++ttl) {
		IPLayer *ip = pkt->GetLayer<IPLayer>();
		PacketModifications *mod = NULL;

		ip->SetSourceIP(sourceIP);
		ip->SetDestinationIP(destinationIP);

		switch (proto) {
		case IP::PROTO:
			reinterpret_cast<IP *>(ip)->SetTTL(ttl);
			break;
		case IPv6::PROTO:
			reinterpret_cast<IPv6 *>(ip)->SetHopLimit(ttl);
			break;
		}
		pkt->PreCraft();

		Packet* rcv = pkt->SendRecv(iface, 1, 3);
		if (rcv) {
			mod = RecvReply(proto, pkt, rcv);
			ip = rcv->GetLayer<IPLayer>();
			if (!resolve)
				cout << ttl << ": " << ip->GetSourceIP() << " ";
			else
				cout << ttl << ": " << GetHostname(ip->GetSourceIP()) << " (" << ip->GetSourceIP() << ") ";
			if (mod)
				mod->Print(cout);
			else
				cout << endl;
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
	int hops_max = 64, dport = 80;
	bool resolve = true;
	int net_proto = IP::PROTO, tr_proto = TCP::PROTO;
	const char *script = NULL;
	const char *probe = NULL;
	Packet *pkt = NULL;
	IPLayer *ip = NULL;

	while ((c = getopt(argc, argv, ":i:m:s:p:d:hn6u")) != -1) {
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
			case '6':
				net_proto = IPv6::PROTO;
				break;
			case 'd':
				dport = strtol(optarg, NULL, 10);
				break;
			case 'u':
				tr_proto = UDP::PROTO;
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

	/* disable libcrafter warnings */
	ShowWarnings = 0;


	if (!probe && !script) {
		pkt = BuildProbe(net_proto, tr_proto, dport);
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
		cerr << "You need to specify at least an IPv4 or IPv6 header" << endl;
		goto out;
	}

	destinationIP = destination = ip->GetDestinationIP();
	if ((destinationIP == "0.0.0.0" || destinationIP == "::") && optind < argc) {
		destination = argv[argc-1];
		destinationIP = resolve_name(ip->GetID(), destination);
	}

	iface = iface == "" ? GetDefaultIface(ip->GetID() == IPv6::PROTO) : iface;
	if (iface == "") {
		cerr << "You need to specify an interface" << endl;
		goto usage;
	}

	if (destinationIP == "" || destinationIP == "0.0.0.0" || destinationIP == "::") {
		cerr << "You need to specify a destination" << endl;
		goto out;
	}

	sourceIP = iface_address(ip->GetID(), iface);
	if (sourceIP == "") {
		cerr << "There is no source address for the specified protocol" << endl;
		goto out;
	}

	SendProbe(ip->GetID(), iface, pkt, sourceIP, destinationIP, destination, hops_max, resolve);

out:
	return 0;

usage:
	fprintf(stderr, "Usage:\n"
"  %s [ OPTIONS ] host\n"
"Options are:\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -6                          Use IPv6 for static probe generated\n"
"  -u                          Use UDP for static probe generated\n"
"  -d port                     Use the specified port for static probe\n"
"                              generated. Default is 80.\n"
"  -i device                   Specify a network interface to operate with\n"
"  -m hops_max                 Set the max number of hops (max TTL to be\n"
"                              reached). Default is 30\n"
"  -p probe                    Specify the probe to send.\n"
"  -s script                   Run a script.\n"
"", argv[0]);
	exit(EXIT_FAILURE);
}
