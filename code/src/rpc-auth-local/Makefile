TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = rpc-auth-local
OBJECTS  = rpc_auth_local.cmo
COBJECTS = rpclocal.o
DOBJECTS = rpc_auth_local.mli
ARCHIVE = rpc_auth_local

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

DOC_IGNORABLE = true

INCLUDES += $(INC_RPC) $(INC_NETSYS)

include $(TOP_DIR)/Makefile.rules

include depend
