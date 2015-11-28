TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = equeue-tcl
ARCHIVE  = equeue_tcl
OBJECTS  = uq_tcl.cmo
DOBJECTS = uq_tcl.mli
COBJECTS = tclqueue.o

LINK_OPTIONS = $(EQUEUE_TCL_LIBS)
CC_OPTIONS = $(EQUEUE_TCL_DEFS)

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

DOC_IGNORABLE = true

INCLUDES += $(INC_EQUEUE)
INCLUDES += $(INC_NETSYS)

include $(TOP_DIR)/Makefile.rules

include depend
