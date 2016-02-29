TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME = netstring-pcre
OBJECTS =  netstring_pcre.cmo
DOBJECTS = netstring_pcre.mli

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

DOC_IGNORABLE = true

include $(TOP_DIR)/Makefile.rules

REQUIRES += bytes pcre

include depend
