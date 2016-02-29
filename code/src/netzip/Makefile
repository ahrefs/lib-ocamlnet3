TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME = netzip
OBJECTS =  netgzip.cmo
DOBJECTS = netgzip.mli

INCLUDES = $(INC_NETSTRING)

# -safe-string is intentionally not enabled. At the time of trying this,
# camlzip was not yet ported to bytes.

#OCAMLC_OPTIONS += $(STRING_OPTS)
#OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

REQUIRES += $(ZIP_PROVIDER)

DOC_IGNORABLE = true

include $(TOP_DIR)/Makefile.rules

include depend
