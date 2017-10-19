/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "config.h"
#include "tracebox.h"
#include "crafter/Utils/IPResolver.h"
#include "script.h"
#include "PacketModification.h"
#include "PartialHeader.h"


#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>

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

static bool skip_suid_check = false;

static uint8_t hops_max = 64;
static uint8_t hops_min = 1;

static string destination;
static string iface;
static bool resolve = true;
static bool verbose = false;
bool print_debug = false;
static json_object * jobj = NULL;
static json_object *j_results = NULL;

double tbx_default_timeout = 1;

template<int n> void BuildNetworkLayer(Packet *) { }
template<int n> void BuildTransportLayer(Packet *, int) { }

template<>
void BuildNetworkLayer<IP::PROTO>(Packet *pkt)
{
	IP ip = IP();
	ip.SetIdentification(rand());
	pkt->PushLayer(ip);
}

template<>
void BuildNetworkLayer<IPv6::PROTO>(Packet *pkt)
{
	IPv6 ip = IPv6();
	ip.SetFlowLabel(rand());
	pkt->PushLayer(ip);
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
				memcpy(name, ifa->ifa_name, IF_NAMESIZE);
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

static pcap_t *pd = NULL, *save_d = NULL;
static int rfd;
static pcap_t *rd = NULL;
static pcap_dumper_t *pdumper, *save_dumper = NULL;
static const char *pcap_filename = DEFAULT_PCAP_FILENAME;
#ifdef HAVE_CURL
static const char * upload_url = DEFAULT_URL;
static bool upload = false;
#endif

int openPcap(){
	OpenPcapDumper(DLT_RAW, pcap_filename, save_d, save_dumper);
	if(save_dumper == NULL){
		cerr << "Error while opening pcap file : " << pcap_geterr(save_d) << endl;
		return -1;
	}
	return 0;
}

void writePcap(Packet* p){
	struct pcap_pkthdr hdr;
	hdr.len = p->GetSize();
	hdr.caplen = p->GetSize();
	hdr.ts = p->GetTimestamp();
	pcap_dump(reinterpret_cast<u_char*>(save_dumper), &hdr, p->GetRawPtr());
}

void closePcap(){
	pcap_dump_flush(save_dumper);
	pcap_close(save_d);
	pcap_dump_close(save_dumper);
#ifdef HAVE_CURL
	if (upload) {
		std::cerr << "Uploading pcap to " << upload_url << std::endl;
		curlPost(pcap_filename, upload_url);
	}
#endif
}


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
		delete reply;
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
	try {
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
	} catch (std::runtime_error &ex) { return ""; }
}

static unsigned long timeval_diff(const struct timeval a, const struct timeval b)
{
	return (a.tv_sec - b.tv_sec) * 10e6L + a.tv_usec - b.tv_usec;
}

static int Callback(void *ctx, uint8_t ttl, string& router,
		PacketModifications *mod)
{
	(void)ctx;
	const Packet *probe = mod->orig.get();
	const Packet *rcv = mod->modif.get();
	IPLayer *ip = probe->GetLayer<IPLayer>();

	if (ttl == 1)
		cout << "tracebox to " <<
			ip->GetDestinationIP() << " (" << destination << "): " <<
			(int)hops_max << " hops max" << endl;

	if (rcv) {
		ip = rcv->GetLayer<IPLayer>();
		if (!resolve)
			cout << +(int)ttl << ": " << router << " ";
		else
			cout << (int)ttl << ": " << GetHostname(router) << " (" << router << ") ";
		cout << timeval_diff(rcv->GetTimestamp(), probe->GetTimestamp()) / 1000 << "ms ";
		if (mod) {
			mod->Print(cout, verbose);
			delete mod;
		}
		cout << endl;
	} else
		cout << (int)ttl << ": *" << endl;

	return 0;
}

static int Callback_JSON(void *ctx, uint8_t ttl, string& router,
		PacketModifications *mod)
{
	(void)ctx;
	const Packet *probe = mod->orig.get();
	IPLayer *ip = probe->GetLayer<IPLayer>();

	if (ttl == 1){
		json_object_object_add(jobj,"addr", json_object_new_string(ip->GetDestinationIP().c_str()));
		json_object_object_add(jobj,"name", json_object_new_string(destination.c_str()));
		json_object_object_add(jobj,"max_hops", json_object_new_int(hops_max));
	}

	json_object * hop = json_object_new_object();

	const Packet *rcv = mod->modif.get();
	if (rcv) {
			ip = rcv->GetLayer<IPLayer>();


			json_object_object_add(hop,"hop", json_object_new_int(ttl));
			json_object_object_add(hop,"from", json_object_new_string(router.c_str()));
			json_object_object_add(hop,"delay", json_object_new_int(timeval_diff(rcv->GetTimestamp(), probe->GetTimestamp())));
			if (resolve)
				json_object_object_add(hop,"name", json_object_new_string(GetHostname(router).c_str()));
			if (mod){
				json_object *modif = json_object_new_array();
				json_object *add = json_object_new_array();
				json_object *del = json_object_new_array();
				json_object *ext = NULL;

				mod->Print_JSON(modif, add, del, &ext, verbose);

				json_object_object_add(hop,"Modifications", modif);
				json_object_object_add(hop,"Additions", add);
				json_object_object_add(hop,"Deletions", del);
				if (ext != NULL)
					json_object_object_add(hop, "ICMPExtensions", ext);
				delete mod;
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

IPLayer* probe_sanity_check(const Packet *pkt, string& err, string& iface)
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

int doTracebox(std::shared_ptr<Packet> pkt_shrd, tracebox_cb_t *callback,
		string& err, void *ctx)
{
	Packet* rcv = NULL;
	PacketModifications *mod = NULL;
	string sIP;
	Packet *pkt = pkt_shrd.get();
	IPLayer *ip = probe_sanity_check(pkt, err, iface);
	if (!ip)
		return -1;

	for (uint8_t ttl = hops_min; ttl <= hops_max; ++ttl) {
		switch (ip->GetID()) {
		case IP::PROTO:
			reinterpret_cast<IP *>(ip)->SetTTL(ttl);
			break;
		case IPv6::PROTO:
			reinterpret_cast<IPv6 *>(ip)->SetHopLimit(ttl);
			break;
		default:
			std::cerr << "Could not access the IPLayer from the probe, "
				"aborting." << std::endl;
			return 1;
		}
		pkt->PreCraft();
		if (print_debug) {
			std::cerr << "Filter used at hop " << (int) ttl << ": ";
			pkt->GetFilter(std::cerr);
			std::cerr << std::endl;
		}

		if (isPcap(iface))
			rcv = PcapSendRecv(pkt, iface);
		else{ // Write both pkt & rcv to pcap file
			rcv = pkt->SendRecv(iface, tbx_default_timeout, 3);
			if(!isPcap(iface))
				writePcap(pkt);
		}

		/* If we have a reply then compute the differences */
		if (rcv) {
			if(!isPcap(iface)){
				Packet p;
				/* Removing Ethernet Layer for storage */
				p = rcv->SubPacket(1,rcv->GetLayerCount());
				writePcap(&p);
			}
			sIP = rcv->GetLayer<IPLayer>()->GetSourceIP();
		} else {
			sIP = "";
		}
		mod = PacketModifications::ComputeModifications(pkt_shrd, rcv);

		/* The callback can stop the iteration */
		if (callback && callback(ctx, ttl, sIP, mod))
			return 0;

		/* Stop if we reached the server */
		if (rcv && sIP == ip->GetDestinationIP())
			return 1;
	}
	return 0;
}

int set_tracebox_ttl_range(uint8_t ttl_min, uint8_t ttl_max)
{
	if(!(ttl_min > 0 && (ttl_min <= ttl_max)))
		return -1;

	hops_min = ttl_min;
	hops_max = ttl_max;
	return 0;
}

uint8_t get_min_ttl() { return hops_min; };
uint8_t get_max_ttl() { return hops_max; };

int main(int argc, char *argv[])
{
	int c;
	int ret = EXIT_SUCCESS;
	int dport = 80;
	int net_proto = IP::PROTO, tr_proto = TCP::PROTO;
	const char *script = NULL;
	const char *probe = NULL;
	Packet *pkt = NULL;
	string err;
	bool inline_script = false;
	PartialTCP::register_type();

	tracebox_cb_t *callback = Callback;

	/* disable libcrafter warnings */
	ShowWarnings = 0;
	while ((c = getopt(argc, argv, "Sl:i:M:m:s:p:d:f:hnv6uwjt:VD"
#ifdef HAVE_CURL
					"Cc:"
#endif
					)) != -1) {
		switch (c) {
			case 'S':
				skip_suid_check = true;
				break;
			case 'i':
				iface = optarg;
				break;
			case 'M':
				hops_min = strtol(optarg, NULL, 10);
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
#ifdef HAVE_CURL
			case 'c':
				upload_url = optarg;
				upload = true;
				break;
			case 'C':
				upload = true;
				break;
#endif
			case 'f' :
				pcap_filename = optarg;
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
			case 't':
				tbx_default_timeout = strtod(optarg, NULL);
				break;
			case 'V':
				std::cerr << _REV_PARSE << std::endl;
				return 0;
			case 'D':
				print_debug = true;
				break;
			case ':':
				std::cerr << "Option `-" << (char)optopt
							<< "' requires an argument!" << std::endl;
				goto usage;
				break;
			case '?':
				std::cerr << "Unknown option `-" << (char)optopt
							<< "'." << std::endl;
			default:
				goto usage;
		}
	}

    if (set_tracebox_ttl_range(hops_min, hops_max) < 0) {
		cerr << "Cannot use the specified TTL range: [" << hops_min << ", " << hops_max << "]" << std::endl;
		goto usage;
	}

	if (!skip_suid_check && getuid() != 0) {
		cerr << "tracebox requires superuser permissions!" << endl;
		goto usage;
	}

	if (optind < argc) {
		destination = argv[optind];
	} else if (!inline_script && ! script) {
		cerr << "You must specify a destination host" << endl;
		goto usage;
	}

	if(openPcap()){
		return EXIT_FAILURE;
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

	if (doTracebox(std::shared_ptr<Packet>(pkt), callback, err) < 0) {
		cerr << "Error: " << err << endl;
		goto usage;
	}

	if (jobj != NULL) {
		json_object_object_add(jobj,"Hops", j_results);
		std::cout << json_object_to_json_string(jobj) << std::endl;
	}
out:
	closePcap();
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
"  -m hops_max                 Set the max number of hops (max TTL to be reached).\n"
"                              Default is 30.\n"
"  -M hops_min                 Set the min number of hops (min TTL to be reached).\n"
"                              Default is 1. \n"
"  -v                          Print more information.\n"
"  -j                          Change the format of the output to JSON.\n"
"  -t timeout                  Timeout to wait for a reply after sending a packet.\n"
"                              Default is 1 sec, accepts decimals.\n"
"  -p probe                    Specify the probe to send.\n"
"  -s script_file              Run a script file.\n"
"  -l inline_script            Run a script.\n"
"  -w                          Show warnings when crafting packets.\n"
#ifdef HAVE_LIBCURL
"  -c server_url               Specify a server where captured packets will be sent.\n"
"  -C                          Same than -c, but use the server at " DEFAULT_URL ".\n"
#endif
"  -f filename                 Specify the name of the pcap file.\n"
"                              Default is " DEFAULT_PCAP_FILENAME ".\n"
"  -S                          Skip the privilege check at the start.\n"
"                              To be used mainly for testing purposes,\n"
"	                           as it will cause tracebox to crash for some\n"
"							   of its features!.\n"
"  -V                          Print tracebox version and exit.\n"
"  -D                          Print debug information.\n"
"\n"
"Every argument passed after the options in conjunction with -s or -l will be passed\n"
"to the lua interpreter and available in a global vector of strings named 'argv',\n"
"in the order they appeared on the command-line.\n"
"\n\nVersion: " _REV_PARSE "\n"
	<< endl;
	return ret;
}
