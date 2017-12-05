TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = netunidata
OBJECTS  = netuniconfig.cmo netunidata.cmo netunichecksums.cmo
DOBJECTS = netunidata.mli

INCLUDES += $(INC_NETSTRING)

MAPPINGS = netmappings_iso.ml \
	   netmappings_other.ml \
	   netmappings_jp.ml \
	   netmappings_kr.ml

ALL_EXTRA = $(MAPPINGS:.ml=.cmo) netuniinit.cmo
OPT_EXTRA = $(MAPPINGS:.ml=.cmx) netuniinit.cmx
ifeq ($(HAVE_SHARED),1)
OPT_EXTRA += $(MAPPINGS:.ml=.cmxs) netuniinit.cmxs
endif

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

include $(TOP_DIR)/Makefile.rules

.SUFFIXES: .cmxs

.cmx.cmxs:
	$(OCAMLOPT) -linkall -shared -I . -o $@ $<

include depend
