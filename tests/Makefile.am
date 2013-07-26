
SUBDIRS = tools

click_configs_in = \
	labs/test0.in \
	labs/test1.in

click_configs = $(click_configs_in:.in=.click)
tracebox_out  = $(click_configs:.click=.out)
tracebox_args = $(click_configs:.click=.args)
input_pcap = $(abs_builddir)/.in.pcap
output_pcap = $(abs_builddir)/.out.pcap

do_subst = $(SED) -e 's,[@]incap[@],$(output_pcap),g' \
                  -e 's,[@]outcap[@],$(input_pcap),g'

AM_TESTS_ENVIRONMENT = \
	INPUT=$(input_pcap) \
	OUTPUT=$(output_pcap) \
	HOP_LIMIT=64 \
	DEST_IP=1.2.3.4 \
	CLICK=$(abs_top_builddir)/tests/tools/click/userlevel/click \
	TRACEBOX=$(abs_top_builddir)/src/tracebox/tracebox \
	LAB_DIR=$(abs_srcdir)/labs

LOG_COMPILER = \
	$(srcdir)/runtest

TESTS_ENVIRONMENT = \
	$(AM_TESTS_ENVIRONMENT) \
	$(LOG_COMPILER)

TESTS = $(click_configs)

EXTRA_DIST = \
	$(LOG_COMPILER) \
	$(click_configs_in) \
	$(tracebox_out) \
	$(tracebox_args)

CLEANFILES = $(click_configs)

SUFFIXES = .in .click

$(click_configs_in): $(tracebox_out) $(tracebox_args)

.in.click:
	@mkdir -p $(builddir)/labs
	$(do_subst) < $(srcdir)/$< > $(builddir)/$@
