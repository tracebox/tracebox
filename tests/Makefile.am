
SUBDIRS = tools

click_configs_in = \
	labs/test0.in \
	labs/test1.in \
	labs/BASIC.in \
	labs/MSS.in \
	labs/IPID.in \
	labs/SEQ.in \
	labs/WIN.in \
	labs/ECN.in \
	labs/LIMITED.in \
	labs/MULTI1.in \
	labs/NAT.in

click_configs = $(click_configs_in:.in=.click)
test_scripts = $(click_configs:.click=.sh)
tracebox_out  = $(click_configs:.click=.out)
tracebox_args = $(click_configs:.click=.args)

TESTS = $(test_scripts)

EXTRA_DIST = \
	runtest.in \
	$(click_configs_in) \
	$(tracebox_out) \
	$(tracebox_args) \
	labs/NAT.in.args

CLEANFILES = \
	$(click_configs) \
	$(test_scripts)

SUFFIXES = .in .click .sh .in.args .args

$(test_scripts): $(click_configs) runtest.in

$(click_configs_in): $(tracebox_out) $(tracebox_args)

.in.click:
	@mkdir -p $(builddir)/labs
	$(SED) -e 's,[@]incap[@],$@.out.pcap,g' \
	       -e 's,[@]outcap[@],$@.in.pcap,g' \
	       < $< > $@

.click.sh:
	$(SED) -e 's,[@]config[@],$(builddir)/$<,g' \
	       -e 's,[@]lab_dir[@],$(abs_srcdir)/labs,g' \
	       -e 's,[@]lab_dir_alt[@],$(abs_builddir)/labs,g' \
	       -e 's,[@]click[@],$(abs_top_builddir)/tests/tools/click/userlevel/click,g' \
	       -e 's,[@]tracebox[@],$(abs_top_builddir)/src/tracebox/tracebox,g' \
	       < $(srcdir)/runtest.in > $@
	chmod +x $@

.in.args.args:
	$(SED) -e 's,[@]example_dir[@],$(top_srcdir)/src/tracebox/examples,g' \
	< $< > $@
