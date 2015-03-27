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
#include <queue>
#include <cstdlib>
#include <unistd.h>
extern "C" {
	#include <pthread.h>
	#include <semaphore.h>
	#include <signal.h>
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

static void _crash(const char *m)
{
	std::perror(m);
	exit(EXIT_FAILURE);
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
	pthread_t thread;
	sem_t full;
	pthread_mutex_t mutex;
	std::queue<Crafter::Packet*> packets;

	rcv_handler handler;
	void *ctx;
	bool sniff;

	Sniffer_private(const std::vector<const char*> &k, rcv_handler h)
		: q(next_q), handler(h), sniff(false)
	{
		int err;
		if (sem_init(&full, 0, 0) == -1)
			_crash("Failed to init semaphore for the Sniffer");
		if ((err = pthread_mutex_init(&mutex, NULL))) {
			errno = err;
			_crash("Failed to init mutex for the Sniffer");
		}

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

	~Sniffer_private()
	{
		sem_destroy(&full);
		pthread_cancel(thread);
		pthread_mutex_destroy(&mutex);
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

int Sniffer_private::nfq_cb(struct nfq_q_handle *qh,
		struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	(void)nfmsg;
	Sniffer_private *s = static_cast<Sniffer_private*>(data);
	nfqnl_msg_packet_hdr *header;
	uint32_t id = 0;
	uint16_t lltype = 0;
	int len, err;
	unsigned char *payload;

	if (!(header = nfq_get_msg_packet_hdr(nfa)))
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	id = ntohl(header->packet_id);
	lltype = ntohs(header->hw_protocol);

  	if ((len = nfq_get_payload(nfa, &payload))) {
		Crafter::Packet *p = new Crafter::Packet(payload, len, lltype);
		if ((err = pthread_mutex_lock(&s->mutex))) {
			errno = err;
			_crash("sniffer::nfq_cb::mutex_lock");
		}
		s->packets.push(p);
		if (sem_post(&s->full))
		 /* Maximum semaphore value exceeded,
		  * reduce the queue to preserve integrity (=DROP packet)... */
			s->packets.pop();
		if ((err = pthread_mutex_unlock(&s->mutex))) {
			errno = err;
			_crash("sniffer::nfq_cb::mutex_unlock");
		}
	}
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

TbxSniffer::TbxSniffer(const std::vector<const char*> &k, rcv_handler h)
	: d(new Sniffer_private(k, h)) {}

TbxSniffer::~TbxSniffer() { delete d; }

void TbxSniffer::stop()
{
	d->sniff = false;
}

static void* _start_queue(void *v)
{
	Sniffer_private *d = static_cast<Sniffer_private*>(v);
	int rv, fd, err;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[4096] __attribute__ ((aligned));

	h = nfq_open();
	if (!h)
		_crash("error during nfq_open()");

	if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_unbind_pf(h, AF_INET6) < 0)
		_crash("error during nfq_unbind_pf()");

	if (nfq_bind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET6) < 0)
		_crash("error during nfq_bind_pf()");

	qh = nfq_create_queue(h,  d->q, &Sniffer_private::nfq_cb, d);
	if (!qh)
		_crash("error during nfq_create_queue()");

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
		_crash("can't set packet_copy mode");

	fd = nfq_fd(h);

	if (d->add_rule())
		_crash("The call to iptables failed!");

	fd_set set;
	do {
		struct timeval tv = { 1, 0 };
		FD_SET(fd, &set);
		err = select(fd+1, &set, NULL, NULL, &tv);
		if (!err)
			continue;
		if (err > 0)
			rv = recv(fd, buf, sizeof(buf), 0);
		else
			break;
		if (rv > 0)
			nfq_handle_packet(h, buf, rv);
		else
			break;
	}
	while (d->sniff && !_killed);

	if(d->remove_rule())
		_crash("Failed to remove the iptables rule");

	d->sniff = false;
	sem_post(&d->full);

	nfq_destroy_queue(qh);
	nfq_close(h);

	pthread_exit(0);
}

int TbxSniffer::start(void *ctx)
{
	int err;

	if (d->sniff)
		_crash("The Sniffer is already started!");

	d->ctx = ctx;

	struct sigaction sa, old_sa;
	sa.sa_handler = _sig_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, &old_sa) == -1)
	   _crash("Cannot register a SIGINT handler");

	if ((err = pthread_create(&d->thread, NULL, _start_queue, d))) {
		errno = err;
		_crash("Cannot start thread for Sniffer queue");
	}

	d->sniff = true;
	while (d->sniff && !_killed) {
		struct timespec t = { 1, 0 };
		if (sem_timedwait(&d->full, &t) == -1) {
			if (errno == ETIMEDOUT)
				continue;
			else
				_crash("Sniffer::start::sem_wait");
		}

		if (!d->sniff)
			break;

		if ((err = pthread_mutex_lock(&d->mutex))) {
			errno = err;
			_crash("Sniffer::start::mutex_lock");
		}
		Crafter::Packet *p = d->packets.front();
		d->packets.pop();
		if ((err = pthread_mutex_unlock(&d->mutex))) {
			errno = err;
			_crash("Sniffer::start::mutex_unlock");
		}
		if (d->handler(p, d->ctx)) {
			d->sniff = false;
		}
	}

	pthread_join(d->thread, NULL);
	sigaction(SIGINT, &old_sa, NULL);

	return 0;
}
