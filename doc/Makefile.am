
@AMDEP_TRUE@@am__include@ @am__quote@generated_files.mk@am__quote@

ldoc_files = html/ldoc.css $(DOCFILES)
nobase_dist_doc_DATA = $(ldoc_files)

EXTRA_DIST = config.ld generated_files.mk $(ldoc_files)

DISTCLEANFILES = Makefile

generated_files_include:
	@echo -n "DOCFILES = "> $(srcdir)/generated_files.mk2
	@find . -maxdepth 5 -type f -name "*.html" | sort | $(AWK) '{printf(" \\\n\t%s", $$0)}' \
		>> $(srcdir)/generated_files.mk2
	@if diff $(srcdir)/generated_files.mk $(srcdir)/generated_files.mk2 >/dev/null 2>&1 ; then \
		echo "generated_files.mk is unchanged" ; \
		rm -f $(srcdir)/generated_files.mk2 ; \
	else \
		mv $(srcdir)/generated_files.mk2 $(srcdir)/generated_files.mk ; \
	fi

all: $(ldoc_files)

force-update-doc: doc-clean $(ldoc_files)

$(ldoc_files): config.ld
	$(MAKE) doc-clean
	ldoc .
	$(MAKE) generated_files_include

doc-clean:
	rm -rf html

.PHONY: generated_files_include force-update-doc doc-clean

