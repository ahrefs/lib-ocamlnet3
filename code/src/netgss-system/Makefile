TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf
# include Makefile.conf

PKGNAME  = netgss-system
OBJECTS  = netgss_bindings.cmo netgss_util.cmo netgss.cmo
COBJECTS = netgss_bindings_stubs.o
DOBJECTS = netgss_bindings.mli

#LINK_OPTIONS = $(NETTLS_GNUTLS_LINK_OPTIONS)
#LINK_OPTIONS = -lgnutls

#CC_OPTIONS = $(NETTLS_GNUTLS_CFLAGS)
CC_OPTIONS_FOR_netgss_bindings_stubs.c = -ccopt -Wno-unused-function

INCLUDES = $(INC_NETSYS) $(INC_NETSTRING)

include $(TOP_DIR)/Makefile.rules

.PHONY: cobjects
cobjects: $(COBJECTS)

netgss_bindings.ml: done_reconfigure
	@:

netgss_bindings.mli: done_reconfigure
	@:

netgss_bindings_stubs.c: done_reconfigure
	@:

done_reconfigure: gssapi.descr gssapi.c gssapi.ml gssapi.mli
	./reconfigure

include depend
