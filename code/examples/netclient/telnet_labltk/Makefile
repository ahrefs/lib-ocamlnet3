#----------------------------------------------------------------------
# specific rules for this package:

SOURCES  = telnet.ml
OBJECTS  = $(SOURCES:.ml=.cmo)
XOBJECTS = $(OBJECTS:.cmo=.cmx)
ARCHIVE  = telnet.cma
XARCHIVE = $(ARCHIVE:.cma=.cmxa)
NAME     = telnet
REQUIRES = netclient, labltk, equeue-tcl

all: $(ARCHIVE)
	$(OCAMLC) -o telnet $(ARCHIVE) main.ml \
		-custom -linkpkg

$(ARCHIVE): $(OBJECTS)
	$(OCAMLC) -a -o $(ARCHIVE) $(OBJECTS)

$(XARCHIVE): $(XOBJECTS) 
	$(OCAMLOPT) -a -o $(XARCHIVE) $(XOBJECTS)

#----------------------------------------------------------------------
# general rules:

OPTIONS   =
OCAMLC    = ocamlfind ocamlc   -package "$(REQUIRES)" \
		$(DEBUG) $(OPTIONS) 
OCAMLOPT  = ocamlfind ocamlopt -package "$(REQUIRES)" \
		$(OPTIONS)
OCAMLDEP  = ocamldep $(OPTIONS)
OCAMLLEX  = ocamllex
OCAMLFIND = ocamlfind

DEBUG  =
# Invoke with: make DEBUG=-g

depend: $(SOURCES) 
	$(OCAMLDEP) *.ml >depend

.PHONY: clean
clean:
	rm -f *.cmi *.cmo *.cma *.cmx *.o *.a *.cmxa telnet

.PHONY: distclean
distclean: clean
	rm -f *~ depend depend.pkg

.SUFFIXES: .cmo .cmi .cmx .ml .mli .mll

.ml.cmx:
	$(OCAMLOPT) -c $<

.ml.cmo:
	$(OCAMLC) -c $<

.mli.cmi:
	$(OCAMLC) -c $<

.mll.ml:
	$(OCAMLLEX) $<

*.mli:
	true

include depend
