.PHONY: all

APPS=mbox_list

all: $(APPS)

mbox_list: mbox_list.ml
	ocamlfind ocamlc -custom -g -o $@ -package unix -package netstring -package netclient -linkpkg $<

.PHONY: clean
clean:
	rm -f $(APPS) *.cmi *.cmo
