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

#include "tracebox.h"
#include "crafter/Utils/IPResolver.h"
#include "script.h"
#include "PartialHeader.h"
#include "PacketModification.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

extern "C" {
#include <pcap.h>
#include <ifaddrs.h>
#include <netinet/in.h>
};

#define PCAP_IPv4 "1.1.1.1"
#define PCAP_IPv6 "dead::beef"

#ifndef IN_LOOPBACK
#define	IN_LOOPBACK(a)		((ntohl((long int) (a)) & 0xff000000) == 0x7f000000)
#endif

#define IN6_LOOPBACK(a) \
        (((__const uint32_t *) (a))[0] == 0                                   \
         && ((__const uint32_t *) (a))[1] == 0                                \
         && ((__const uint32_t *) (a))[2] == 0                                \
         && ((__const uint32_t *) (a))[3] == htonl (1))

using namespace Crafter;
using namespace std;

static int hops_max = 64;
static string destination;
static string iface;
static bool resolve = true;
static bool verbose = false;

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
	int fd, af = ipv6 ? AF_INET6 : AF_INET;
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
			char name[IF_NAMESIZE];
			size_t len = ipv6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
			ifa_addr = ipv6 ? (void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr :
					(void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			saddr = ipv6 ? (void *)&((struct sockaddr_in6 *)&sa)->sin6_addr :
					(void *)&((struct sockaddr_in *)&sa)->sin_addr;
			memcpy(name, ifa->ifa_name, IF_NAMESIZE);
			if (!memcmp(ifa_addr, saddr, len)) {
				freeifaddrs(ifaces);
				close(fd);
				return name;
			}
		}
	}

	freeifaddrs(ifaces);
error:
	close(fd);
out:
	return "";
}

bool isPcap(const string& iface)
{
	return iface.compare(0, 5, "pcap:") == 0;
}

bool pcapParse(const string& name, string& output, string& input)
{
	string s = name;
	string delimiter = ":";
	vector<string> tokens;
	size_t pos = 0;

	while ((pos = s.find(delimiter)) != string::npos) {
	    string token = s.substr(0, pos);
	    s.erase(0, pos + 1);
		tokens.push_back(token);
	}
	tokens.push_back(s);

	if (tokens.size() != 3 || tokens[0] != "pcap")
		return false;

	output = tokens[1];
	input = tokens[2];

	return true;
}

static pcap_t *pd = NULL;
static int rfd;
static pcap_t *rd = NULL;
static pcap_dumper_t *pdumper;

Packet* PcapSendRecv(Packet *probe, const string& iface)
{
	struct pcap_pkthdr hdr1, hdr2;
	uint8_t *packet;
	Packet* reply = NULL;
	string in_file, out_file;

	if (!pd && !rd)
		pcapParse(iface, out_file, in_file);

	memset(&hdr1, 0, sizeof(hdr2));
	if (gettimeofday(&hdr2.ts, NULL) < 0)
		return NULL;
	hdr2.len = probe->GetSize();
	hdr2.caplen = probe->GetSize();

	/* Write packet to pcap and wait for reply */
	if (!pd)
		OpenPcapDumper(DLT_RAW, out_file, pd, pdumper);

#ifdef __APPLE__
	/* if MAC OSX -> IP total len must be changed */
	byte copy[probe->GetSize()];
	memcpy(copy, probe->GetRawPtr(), probe->GetSize());

	if (probe->GetLayer<IPLayer>()->GetID() == IP::PROTO) {
		byte tmp = copy[2];
		copy[2] = copy[3];
		copy[3] = tmp;
	}
	DumperPcap(pdumper, &hdr2, copy);
#else
	DumperPcap(pdumper, &hdr2, probe->GetRawPtr());
#endif
	pcap_dump_flush(pdumper);
	if (!rd) {
		char pcap_errbuf[PCAP_ERRBUF_SIZE];

		rd = pcap_open_offline(in_file.c_str(), pcap_errbuf);
		if (rd == NULL) {
			goto error;
		}

		rfd = pcap_get_selectable_fd(rd);
		if (rfd < 0) {
			goto error;
		}
	}

	/* Retrieve the reply from MB or server*/
	packet = (uint8_t *)pcap_next(rd, &hdr1);

	reply = new Packet;
	switch((packet[0] & 0xf0) >> 4) {
	case 4:
		reply->PacketFromIP(packet, hdr1.len);
		break;
	case 6:
		reply->PacketFromIPv6(packet, hdr1.len);
		break;
	default:
		return NULL;
	}

error:
	return reply;
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
		if (isPcap(iface))
			return PCAP_IPv4;
		return GetMyIP(iface);
	case IPv6::PROTO:
		if (isPcap(iface))
			return PCAP_IPv6;
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
			modifs->push_back(new Modification(l1->GetID(), l1->GetField(i), l2->GetField(i)));
	}

	/* TODO do something more clever here
	 * (ex: identify the offset where the change occured)
	 */
	if (l1->GetPayload().GetSize() < l2->GetPayload().GetSize())
		modifs->push_back(new Addition(l1));
	else if (l1->GetPayload().GetSize() > l2->GetPayload().GetSize())
		modifs->push_back(new Deletion(l1));
	else if (memcmp(l1->GetPayload().GetRawPointer(), l2->GetPayload().GetRawPointer(), l1->GetPayload().GetSize()))
		modifs->push_back(new Modification(l1, l2));

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
			modifs->push_back(new Deletion(l1));
		else if (!l1 && l2)
			modifs->push_back(new Addition(l2));
	}

	return modifs;
}

Packet* TrimReplyIPv4(Packet *rcv, bool *partial)
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

Packet* TrimReplyIPv6(Packet *rcv)
{
	IPv6 *ip = GetIPv6(*rcv);

	/* Remove any extension. */
	if ((size_t)ip->GetPayloadLength() + 40 < rcv->GetSize()) {
		RawLayer *raw = GetRawLayer(*rcv);
		int len = raw->GetSize() - (rcv->GetSize() - (ip->GetPayloadLength() + 40));
		RawLayer new_raw(raw->GetPayload().GetRawPointer(), len);

		rcv->PopLayer();
		if (len)
			rcv->PushLayer(new_raw);
	}

	return rcv;
}

PacketModifications* RecvReply(int proto, Packet *pkt, Packet **rcv)
{
	ICMPLayer *icmp = (*rcv)->GetLayer<ICMPLayer>();
	RawLayer *raw = (*rcv)->GetLayer<RawLayer>();
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
		cnt = TrimReplyIPv4(cnt, &partial);
		break;
	case IPv6::PROTO:
		cnt->PacketFromIPv6(*raw);
		cnt = TrimReplyIPv6(cnt);
		break;
	default:
		delete cnt;
		return NULL;
	}

	delete *rcv;
	*rcv = cnt;

	return ComputeDifferences(pkt, cnt, partial);
}

static int Callback(void *ctx, int ttl, string& router,
	const Packet * const probe, Packet *rcv, PacketModifications *mod)
{
	(void)ctx;
	IPLayer *ip = probe->GetLayer<IPLayer>();

	if (ttl == 1)
		cout << "tracebox to " << ip->GetDestinationIP() << " (" << destination << "): " << hops_max << " hops max" << endl;

	if (rcv) {
		ip = rcv->GetLayer<IPLayer>();
		if (!resolve)
			cout << ttl << ": " << router << " ";
		else
			cout << ttl << ": " << GetHostname(router) << " (" << router << ") ";
		if (mod) {
			mod->Print(cout, verbose);
			delete mod;
		}
		cout << endl;
		delete rcv;
	} else
		cout << ttl << ": *" << endl;

	return 0;
}

bool validIPv4Address(const string& ipAddress) {
        struct in_addr addr4;
        inet_pton(AF_INET, ipAddress.c_str(), &(addr4));
        return !IN_LOOPBACK(addr4.s_addr);
}

bool validIPv6Address(const string& ipAddress) {
        struct in6_addr addr6;
        inet_pton(AF_INET6, ipAddress.c_str(), &addr6);
	return !IN6_LOOPBACK(&addr6);
}

bool validIPAddress(bool ipv6, const string& ipAddress)
{
	if (ipv6)
		return validIPv6Address(ipAddress);
	else
		return validIPv4Address(ipAddress);
}

int doTracebox(Packet *pkt, tracebox_cb_t *callback, string& err, void *ctx)
{
	IPLayer *ip = pkt->GetLayer<IPLayer>();
	string sourceIP;
	string destinationIP;

	ip = pkt->GetLayer<IPLayer>();
	if (!ip) {
		err = "You need to specify at least an IPv4 or IPv6 header";
		return -1;
	}

	destinationIP = ip->GetDestinationIP();
	if ((destinationIP == "0.0.0.0" || destinationIP == "::") && destination != "")
		destinationIP = resolve_name(ip->GetID(), destination);

	iface = iface == "" ? GetDefaultIface(ip->GetID() == IPv6::PROTO) : iface;
	if (iface == "") {
		err = "You need to specify an interface";
		return -1;
	}

	if (destinationIP == "" || destinationIP == "0.0.0.0" || destinationIP == "::") {
		err = "You need to specify a destination";
		return -1;
	}

	if (!validIPAddress(ip->GetID() == IPv6::PROTO, destinationIP)) {
		err = "The specified address is not valid";
		return -1;
	}

	sourceIP = iface_address(ip->GetID(), iface);
	if (sourceIP == "") {
		err = "There is no source address for the specified protocol";
		return -1;
	}

	ip->SetSourceIP(sourceIP);
	ip->SetDestinationIP(destinationIP);

	for (int ttl = 1; ttl <= hops_max; ++ttl) {
		Packet* rcv = NULL;
		PacketModifications *mod = NULL;
		string sIP;

		switch (ip->GetID()) {
		case IP::PROTO:
			reinterpret_cast<IP *>(ip)->SetTTL(ttl);
			break;
		case IPv6::PROTO:
			reinterpret_cast<IPv6 *>(ip)->SetHopLimit(ttl);
			break;
		}
		pkt->PreCraft();

		if (isPcap(iface))
			rcv = PcapSendRecv(pkt, iface);
		else
			rcv = pkt->SendRecv(iface, 1, 3);

		/* If we have a reply then compute the differences */
		if (rcv) {
			sIP = rcv->GetLayer<IPLayer>()->GetSourceIP();
			mod = RecvReply(ip->GetID(), pkt, &rcv);
		}

		/* The callback can stop the iteration */
		if (callback && callback(ctx, ttl, sIP, pkt, rcv, mod))
			return 0;

		/* Stop if we reached the server */
		if (rcv && sIP == destinationIP)
			return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char c;
	int ret = 1;
	int dport = 80;
	int net_proto = IP::PROTO, tr_proto = TCP::PROTO;
	const char *script = NULL;
	const char *probe = NULL;
	Packet *pkt = NULL;
	string err;
	bool inline_script = false;
	bool need_su = true;

	/* disable libcrafter warnings */
	ShowWarnings = 0;
	while ((c = getopt(argc, argv, ":l:i:m:s:p:d:hnv6uw")) != -1) {
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
			case 'v':
				verbose = true;
				break;
			case 'h':
				ret = 0;
				goto usage;
			case 'w':
				ShowWarnings = 1;
				break;
			case 'l':
				script = optarg;
				inline_script = true;
				break;
			case ':':
				cerr << "missing option argument" << endl;
			default:
				goto usage;
		}
	}

	if (need_su && getuid() != 0) {
		fprintf(stderr, "tracebox requires superuser permissions!\n");
		return 1;
	}

	if (optind < argc)
		destination = argv[argc-1];

	if (!probe && !script) {
		pkt = BuildProbe(net_proto, tr_proto, dport);
	} else if (probe && !script) {
		string cmd = probe;
		pkt = script_packet(cmd);
	} else if (script && !probe) {
		if (inline_script)
			script_exec(script);
		else
			script_execfile(script);
		goto out;
	} else {
		cerr << "You cannot specify a script and a probe at the same time" << endl;
		goto usage;
	}

	if (!pkt)
		goto out;

	if (doTracebox(pkt, Callback, err) < 0) {
		cerr << "Error: " << err << endl;
		goto usage;
	}
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
"                              reached). Default is 30.\n"
"  -v                          Print more information.\n"
"  -p probe                    Specify the probe to send.\n"
"  -s script_file              Run a script file.\n"
"  -l inline_script            Run a script.\n"
"  -w                          Show warnings when crafting packets.\n"
"", argv[0]);
	return ret;
}
