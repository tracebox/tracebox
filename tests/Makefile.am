
SUBDIRS = tools

lua_scripts = lua/refcounting.lua \
			  lua/sleep.lua \
			  lua/dns.lua \
			  lua/packet.lua \
			  lua/arguments.lua

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
	labs/JSON.in \
	labs/MULTI1.in

click_configs_in_args = \
	labs/NAT.in

click_configs = \
	$(click_configs_in:.in=.click) \
	$(click_configs_in_args:.in=.click)
test_scripts = 	$(click_configs:.click=.sh)
tracebox_out  = $(click_configs:.click=.out)
tracebox_args = $(click_configs:.click=.args)
test_lua = $(lua_scripts:.lua=.sh)

TESTS = $(test_scripts) $(test_lua)

EXTRA_DIST = \
	runtest.in \
	lua.in \
	$(click_configs_in) \
	$(click_configs_in_args) \
	$(lua_scripts) \
	$(tracebox_out) \
	$(click_configs_in:.in=.args) \
	$(click_configs_in_args:.in=.in.args)

CLEANFILES = \
	$(click_configs) \
	$(test_scripts) \
	$(test_lua) \
	$(click_configs_in_args:.in=.args)

SUFFIXES = .in .click .sh .in.args .args .lua

$(test_lua): $(lua_scripts) lua.in

$(test_scripts): $(click_configs) runtest.in

$(click_configs_in): $(tracebox_out) $(tracebox_args)

.in.click:
	@mkdir -p $(builddir)/labs
	$(SED) -e 's,[@]incap[@],$@.out.pcap,g' \
	       -e 's,[@]outcap[@],$@.in.pcap,g' \
	       < $(srcdir)/$(subst $(srcdir)/,,$<) > $@

.click.sh:
	$(SED) -e 's,[@]config[@],$(builddir)/$<,g' \
	       -e 's,[@]lab_dir[@],$(abs_srcdir)/labs,g' \
	       -e 's,[@]lab_dir_alt[@],$(abs_builddir)/labs,g' \
	       -e 's,[@]click[@],$(abs_top_builddir)/tests/tools/click/userlevel/click,g' \
	       -e 's,[@]tracebox[@],sudo $(abs_top_builddir)/src/tracebox/tracebox,g' \
	       < $(srcdir)/runtest.in > $@
	chmod +x $@

.in.args.args:
	@mkdir -p $(builddir)/labs
	$(SED) -e 's,[@]example_dir[@],$(top_srcdir)/src/tracebox/examples,g' \
	< $(srcdir)/$(subst $(srcdir)/,,$<) > $@

.lua.sh:
	$(SED) -e 's,[@]args[@],$(srcdir)/$<.in,g' \
	       -e 's,[@]tracebox[@],sudo $(abs_top_builddir)/src/tracebox/tracebox,g' \
	       -e 's,[@]script[@],$(srcdir)/$<,g' \
	       < $(srcdir)/lua.in > $@
	chmod +x $@
