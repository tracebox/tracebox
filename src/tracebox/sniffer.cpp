/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#include "sniffer.h"

#include <sstream>
#include <iostream>
#include <ostream>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
extern "C" {
	#include <sys/wait.h>
	#include <netinet/in.h>
	#include <linux/types.h>
	#include <linux/netfilter.h>
}
#include <libnetfilter_queue/libnetfilter_queue.h>

static volatile sig_atomic_t _killed = 0;

void _sig_handler(int unused) {
	(void)unused;
	_killed = 1;
}

static inline int _error(const char *m)
{
	std::cerr << m << std::endl;
	return 1;
}

static int _exec(char* const *args)
{
	pid_t child_pid, wpid;
	int child_status;

	child_pid = fork();
	if(child_pid == 0) { /* In child */
		execvp(args[0], args);
		/* Shouldn't be reached ... */
		exit(EXIT_FAILURE);
	} else { /* In parent */
		do {
			wpid = wait(&child_status);
		} while(wpid > 0);
	}
	return child_status;
}

static int iptables(std::vector<std::string> &args)
{
	int err;
	for( std::vector<std::string>::const_iterator i = args.begin(); i != args.end(); ++i)
    	std::cerr << *i << " ";
	std::cerr << std::endl;
	const char **argv = new const char* [args.size()+2];
	for (size_t i = 0; i < args.size(); ++i)
		argv[i+1] = args[i].c_str();
    argv[args.size()+1] = NULL;
	argv[0] = "iptables";
	if ((err = _exec((char* const*)argv))) {
		delete argv;
		return err;
	}
	argv[0] = "ip6tables";
	err = _exec((char* const*)argv);
	delete argv;
	return err;
}


struct Sniffer_private {
	static int next_q;

	int q;
	std::vector<std::string> key;
	rcv_handler handler;
	void *ctx;
	bool sniff;

	Sniffer_private(const std::vector<const char*> &k, rcv_handler h)
		: q(next_q), handler(h), sniff(false)
	{
		key.reserve(k.size() + 6);
		std::vector<const char*>::const_iterator it;
		for (it = k.begin(); it != k.end(); ++it)
			key.push_back(std::string(*it));
		key.push_back("-j");
		key.push_back("NFQUEUE");
		key.push_back("--queue-num");
		std::stringstream s;
		s << q;
		key.push_back(std::string(s.str()));
		key.push_back("-A");
		key.push_back("INPUT");
		++next_q;
	}

	int add_rule()
	{
		key[key.size() - 2] = "-A";
		return iptables(key);
	}

	int remove_rule()
	{
		key[key.size() - 2] = "-D";
		return iptables(key);
	}

	static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data);
};
int Sniffer_private::next_q = 0;

TbxSniffer::TbxSniffer(const std::vector<const char*> &k, rcv_handler h)
	: d(new Sniffer_private(k, h)) {}
TbxSniffer::~TbxSniffer() { delete d; }

void TbxSniffer::stop() { d->sniff = false; }

int Sniffer_private::nfq_cb(struct nfq_q_handle *qh,
		struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	(void)nfmsg;
	Sniffer_private *s = static_cast<Sniffer_private*>(data);
	nfqnl_msg_packet_hdr *header;
	uint32_t id = 0;
	uint16_t lltype = 0;
	int len;
	unsigned char *payload;

	if (!(header = nfq_get_msg_packet_hdr(nfa)))
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	id = ntohl(header->packet_id);
	lltype = ntohs(header->hw_protocol);

  	if ((len = nfq_get_payload(nfa, &payload))) {
		Crafter::Packet *p = new Crafter::Packet(payload, len, lltype);
		int err = s->handler(p, s->ctx);
		if (!err)
			nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		if (err < 0) {
			nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			s->sniff = false;
			return -1;
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int TbxSniffer::start(void *ctx)
{
	int rv, fd;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[4096] __attribute__ ((aligned));

	if (d->sniff)
		return _error("The Sniffer is already started!");

	d->ctx = ctx;
	h = nfq_open();
	if (!h)
		return _error("error during nfq_open()");

	if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_unbind_pf(h, AF_INET6) < 0)
		return _error("error during nfq_unbind_pf()");

	if (nfq_bind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET6) < 0)
		return _error("error during nfq_bind_pf()");

	qh = nfq_create_queue(h,  d->q, &Sniffer_private::nfq_cb, d);
	if (!qh)
		return _error("error during nfq_create_queue()");

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
		return _error("can't set packet_copy mode");

	fd = nfq_fd(h);
	d->sniff = true;

	if (d->add_rule())
		return _error("The call to iptables failed!");

	struct sigaction sa, old_sa;
	sa.sa_handler = _sig_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, &old_sa) == -1)
	   return _error("Cannot register a SIGINT handler");

	do {
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv > 0)
			nfq_handle_packet(h, buf, rv);
	}
	while (((rv == -1 && errno == EINTR) || rv >= 0) && d->sniff && !_killed);

	sigaction(SIGINT, &old_sa, NULL);

	if(d->remove_rule())
		return _error("Failed to remove the iptables rule");

	d->sniff = false;
	nfq_destroy_queue(qh);
	nfq_close(h);
	return 0;
}
