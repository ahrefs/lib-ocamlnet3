TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf
# include Makefile.conf

PKGNAME  = netgss-system
OBJECTS  = netgss_bindings.cmo netgss_util.cmo netgss.cmo
COBJECTS = netgss_bindings_stubs.o
DOBJECTS = netgss_bindings.mli netgss.mli

LINK_OPTIONS = $(NETGSS_LINK_OPTIONS)
#LINK_OPTIONS = -lkrb5

CC_OPTIONS = $(NETGSS_CFLAGS)
CC_OPTIONS_FOR_netgss_bindings_stubs.c = -ccopt -Wno-unused-function \
    -ccopt -DNETGSS_VARIANT_"$(NETGSS_VARIANT)"

INCLUDES = $(INC_NETSYS) $(INC_NETSTRING)

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

DOC_IGNORABLE = true

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
