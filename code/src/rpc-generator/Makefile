TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = rpc-generator
ARCHIVE  = rpc_generator
OBJECTS  = config.cmo syntax.cmo options.cmo parser.cmo lexer.cmo rename.cmo \
           generate.cmo direct.cmo
DOBJECTS = 

ALL_EXTRA = ocamlrpcgen$(EXEC_SUFFIX) rpcgen-packlist

PACKLIST = rpcgen-packlist

INCLUDES += $(INC_NETSTRING)

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

include $(TOP_DIR)/Makefile.rules

ocamlrpcgen$(EXEC_SUFFIX): $(ARCHIVE).cma main.cmo
	rm -f ocamlrpcgen ocamlrpcgen$(EXEC_SUFFIX)
	OCAMLPATH="..$(PATH_SEP)$$OCAMLPATH" \
	$(OCAMLC) -custom -o ocamlrpcgen \
		-package unix,netstring,$(REGEXP_PROVIDER) \
		$(ARCHIVE).cma main.cmo -linkpkg

rpcgen-packlist:
	echo $(BINDIR)/ocamlrpcgen >rpcgen-packlist

include depend
