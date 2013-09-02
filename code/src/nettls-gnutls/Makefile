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

INCLUDES = $(INC_NETSYS)

include $(TOP_DIR)/Makefile.rules

.PHONY: cobjects
cobjects: $(COBJECTS)

include depend
