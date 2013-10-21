TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf
# include Makefile.conf

PKGNAME  = nettls-gnutls
OBJECTS  = nettls_gnutls_bindings.cmo \
           nettls_gnutls.cmo
COBJECTS = nettls_gnutls_bindings_stubs.o
DOBJECTS = nettls_gnutls_bindings.mli

#LINK_OPTIONS = $(NETTLS_GNUTLS_LINK_OPTIONS)
LINK_OPTIONS = -lgnutls

CC_OPTIONS_FOR_nettls_gnutls_bindings_stubs.c = -ccopt -Wno-unused-function

INCLUDES = $(INC_NETSYS) $(INC_NETSTRING)

include $(TOP_DIR)/Makefile.rules

.PHONY: cobjects
cobjects: $(COBJECTS)

nettls_gnutls_bindings.ml: done_reconfigure
	@:

nettls_gnutls_bindings.mli: done_reconfigure
	@:

nettls_gnutls_bindings_stubs.c: done_reconfigure
	@:

done_reconfigure: gnutls.descr gnutls.c gnutls.ml gnutls.mli
	./reconfigure

include depend
