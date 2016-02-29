TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = rpc-xti
ARCHIVE  = rpc_xti
OBJECTS  = rpc_xti_client.cmo
COBJECTS = rpcxti.o
DOBJECTS = rpc_xti_client.mli

INCLUDES += $(INC_RPC)

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

DOC_IGNORABLE = true

include $(TOP_DIR)/Makefile.rules

include depend
