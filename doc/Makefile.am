ldoc_files =html/ldoc.css \
			html/index.html \
			html/modules/Globals.html \
			html/classes/Raw.html \
			html/classes/DNS.html \
			html/classes/TCP.html \
			html/classes/Base_Object.html \
			html/classes/Packet.html \
			html/classes/IPOption.html \
			html/classes/IP.html \
			html/classes/TCPTFO.html \
			html/classes/TCPOption.html \
			html/classes/PacketModifications.html \
			html/classes/IPv6.html \
			html/classes/IPv6SegmentRoutingHeader.html \
			html/classes/__cpp_obj.html \
			html/classes/TCPTimestamp.html \
			html/classes/UDP.html \
			html/classes/FWFilter.html \
			html/classes/TbxSniffer.html \
			html/classes/ICMP.html

nobase_dist_doc_DATA = $(ldoc_files)

EXTRA_DIST = config.ld $(ldoc_files)
DISTCLEANFILES = Makefile

all: $(ldoc_files)

force-update-doc: doc-clean $(ldoc_files)

$(ldoc_files): config.ld
	cd $(abs_builddir) && ldoc .

doc-clean:
	rm -rf html

.PHONY: generated_files_include force-update-doc doc-clean

