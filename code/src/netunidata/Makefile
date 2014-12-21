TOP_DIR=../..

PKGNAME  = netunidata
OBJECTS  = netuniconfig.cmo netunidata.cmo netunichecksums.cmo
DOBJECTS = netunidata.mli

INCLUDES += $(INC_NETSTRING)

INSTOTHER = install-netdb
PACKLIST = netdb-packlist

MAPPINGS = netmappings_iso.ml \
	   netmappings_other.ml \
	   netmappings_jp.ml \
	   netmappings_kr.ml

ALL_EXTRA = $(MAPPINGS:.ml=.cmo) netuniinit.cmo
OPT_EXTRA = $(MAPPINGS:.ml=.cmx) netuniinit.cmx

INSTALL_EXTRA = $(ALL_EXTRA) $(OPT_EXTRA)

netdb-packlist:
	test -d netdb
	(cd netdb && ls *.netdb) | \
	{ while read f; do echo "$(NET_DB_DIR)/$$f"; done; } >netdb-packlist

.PHONY: install-netdb
install-netdb:
	mkdir -p "$(DESTDIR)$(NET_DB_DIR)"
	cp netdb/*.netdb "$(DESTDIR)$(NET_DB_DIR)"
	@echo "Installed .netdb files into $(DESTDIR)$(NET_DB_DIR)"

include $(TOP_DIR)/Makefile.rules

include depend
