/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */


#include "tracebox.h"
#include "crafter/Utils/IPResolver.h"
#include "script.h"
#include "PacketModification.h"


#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#ifdef HAVE_LIBJSON
#include <json/json.h>
#endif
#ifdef HAVE_JSONC
#include <json-c/json.h>
#endif

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
//static bool json_output = false;
static json_object * jobj = NULL;
static json_object *j_results = NULL;

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

string GetDefaultIface(bool ipv6, const string &addr)
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
		inet_pton(af, addr.c_str(), &sin6->sin6_addr);
		sin6->sin6_port = htons(666);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
		sin->sin_family = af;
		sa_len = sizeof(*sin);
		inet_pton(af, addr.c_str(), &sin->sin_addr);
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
			if (!memcmp(ifa_addr, saddr, len)) {
				strncpy(name, ifa->ifa_name, IF_NAMESIZE);
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

static int Callback_JSON(void *ctx, int ttl, string& router,
		const Packet * const probe, Packet *rcv, PacketModifications *mod)
{
	IPLayer *ip = probe->GetLayer<IPLayer>();

	if (ttl == 1){
		json_object_object_add(jobj,"addr", json_object_new_string(ip->GetDestinationIP().c_str()));
		json_object_object_add(jobj,"name", json_object_new_string(destination.c_str()));
		json_object_object_add(jobj,"max_hops", json_object_new_int(hops_max));
	}

	json_object * hop = json_object_new_object();

	if (rcv) {
			ip = rcv->GetLayer<IPLayer>();


			json_object_object_add(hop,"hop", json_object_new_int(ttl));
			json_object_object_add(hop,"from", json_object_new_string(router.c_str()));
			if (resolve)
				json_object_object_add(hop,"name", json_object_new_string(GetHostname(router).c_str()));
			if (mod){
				json_object *modif = json_object_new_array();
				json_object *icmp = json_object_new_array();
				json_object *add = json_object_new_array();
				json_object *del = json_object_new_array();

				mod->Print_JSON(modif, icmp, add, del, verbose);

				json_object_object_add(hop,"Modifications", modif);
				json_object_object_add(hop,"Aditions", add);
				json_object_object_add(hop,"Deletions", del);

			}
	}
	else{
		json_object_object_add(hop,"hop", json_object_new_int(ttl));
		json_object_object_add(hop,"from", json_object_new_string("*"));
	}

	json_object_array_add(j_results,hop);

	return 0;
}

bool validIPAddress(bool ipv6, const string& ipAddress)
{
	if (ipv6)
		return validateIpv6Address(ipAddress);
	else
		return validateIpv4Address(ipAddress);
}

IPLayer* probe_sanity_check(Packet *pkt, string& err, string& iface)
{
	IPLayer *ip = pkt->GetLayer<IPLayer>();
	string sourceIP;
	string destinationIP;

	if (!ip) {
		err = "You need to specify at least an IPv4 or IPv6 header";
		return NULL;
	}

	destinationIP = ip->GetDestinationIP();
	sourceIP = ip->GetSourceIP();
	if ((destinationIP == "0.0.0.0" || destinationIP == "::") && destination != "")
		destinationIP = resolve_name(ip->GetID(), destination);

	if (destinationIP == "" || destinationIP == "0.0.0.0" || destinationIP == "::") {
		err = "You need to specify a destination";
		return NULL;
	}

	if (!validIPAddress(ip->GetID() == IPv6::PROTO, destinationIP)) {
		err = "The specified destination address is not valid";
		return NULL;
	}

	iface = iface == "" ? GetDefaultIface(ip->GetID() == IPv6::PROTO, destinationIP) : iface;
	if (iface == "") {
		err = "You need to specify an interface as there is no default one";
		return NULL;
	}

	if (sourceIP == "" || sourceIP == "0.0.0.0" || sourceIP == "::") {
		sourceIP = iface_address(ip->GetID(), iface);
		if (sourceIP == "") {
			err = "There is no source address for the specified protocol";
			return NULL;
		}
		ip->SetSourceIP(sourceIP);
	} else if (!validIPAddress(ip->GetID() == IPv6::PROTO, sourceIP)) {
		err = "The specified source address is not valid";
		return NULL;
	}

	ip->SetDestinationIP(destinationIP);
	return ip;
}

int doTracebox(Packet *pkt, tracebox_cb_t *callback, string& err, void *ctx)
{
	IPLayer *ip = probe_sanity_check(pkt, err, iface);
	if (!ip)
		return -1;

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
			mod = PacketModifications::ComputeModifications(pkt, &rcv);
		}

		/* The callback can stop the iteration */
		if (callback && callback(ctx, ttl, sIP, pkt, rcv, mod))
			return 0;

		/* Stop if we reached the server */
		if (rcv && sIP == ip->GetDestinationIP())
			return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char c;
	int ret = EXIT_SUCCESS;
	int dport = 80;
	int net_proto = IP::PROTO, tr_proto = TCP::PROTO;
	const char *script = NULL;
	const char *probe = NULL;
	Packet *pkt = NULL;
	string err;
	bool inline_script = false;

	tracebox_cb_t *callback = Callback;

	/* disable libcrafter warnings */
	ShowWarnings = 0;
	while ((c = getopt(argc, argv, ":l:i:m:s:p:d:hnv6uwj")) != -1) {
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
			case 'j':
				callback = Callback_JSON;
				jobj = json_object_new_object();
				j_results = json_object_new_array();
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

	if (getuid() != 0) {
		cerr << "tracebox requires superuser permissions!" << endl;
		return 1;
	}

	if (optind < argc)
		destination = argv[optind];
	else if (!inline_script && ! script) {
		cerr << "You must specify a destination host" << endl;
		return 1;
	}

	if (!probe && !script) {
		pkt = BuildProbe(net_proto, tr_proto, dport);
	} else if (probe && !script) {
		string cmd = probe;
		pkt = script_packet(cmd);
	} else if (script && !probe) {
		int rem_argc = argc - optind;
		char **rem_argv = rem_argc ? &argv[optind] : NULL;
		if (inline_script)
			ret = script_exec(script, rem_argc, rem_argv);
		else
			ret = script_execfile(script, rem_argc, rem_argv);
		goto out;
	} else {
		cerr << "You cannot specify a script and a probe at the same time" << endl;
		goto usage;
	}

	if (!pkt)
		return EXIT_FAILURE;

	if (doTracebox(pkt, callback, err) < 0) {
		cerr << "Error: " << err << endl;
		goto usage;
	}

	delete pkt;

	if (jobj != NULL) {
		json_object_object_add(jobj,"Hops", j_results);
		printf ("%s\n",json_object_to_json_string(jobj));
	}
out:
	return ret;

usage:
	cerr << "Usage:\n"
"  " << argv[0] << " [ OPTIONS ] {host | [Lua argument list]}\n"
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
"  -j                          Change the format of the output to JSON.\n"
"  -p probe                    Specify the probe to send.\n"
"  -s script_file              Run a script file.\n"
"  -l inline_script            Run a script.\n"
"  -w                          Show warnings when crafting packets.\n"
"\n"
"Every argument passed after the options in conjunction with -s or -l will be passed\n"
"to the lua interpreter and available in a global vector of strings named 'argv',\n"
"in the order they appeared on the command-line.\n"
	<< endl;
	return ret;
}
