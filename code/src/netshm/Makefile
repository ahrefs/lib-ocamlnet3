TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME = netshm
OBJECTS = netshm.cmo netshm_data.cmo netshm_hashtbl.cmo netshm_array.cmo
DOBJECTS = netshm.mli netshm_data.mli netshm_hashtbl.mli netshm_array.mli \
	   netshm_intro.txt

INCLUDES += $(INC_NETSYS)

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

include $(TOP_DIR)/Makefile.rules

include depend
