TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

OBJECTS = cppo_types.cmo \
	  cppo_command.cmo \
	  cppo_parser.cmo \
	  cppo_lexer.cmo \
	  cppo_eval.cmo \
	  cppo_version.cmo

PKGNAME = cppo

ALL_EXTRA = cppo$(EXEC_SUFFIX)

# only for checking whether we are compatible
#OCAMLC_OPTIONS = -safe-string

include $(TOP_DIR)/Makefile.rules

cppo$(EXEC_SUFFIX): $(ARCHIVE).cma cppo_main.cmo
	rm -f cppo cppo$(EXEC_SUFFIX)
	$(OCAMLC) -package unix,bytes -linkpkg -custom -o cppo $(ARCHIVE).cma cppo_main.cmo

include depend

