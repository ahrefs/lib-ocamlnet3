TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME = netcamlbox
OBJECTS =  netcamlbox.cmo
DOBJECTS = netcamlbox.mli

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

INCLUDES = $(INC_NETSYS)

include $(TOP_DIR)/Makefile.rules

include depend
