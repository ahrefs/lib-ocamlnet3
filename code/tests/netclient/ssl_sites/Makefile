all: ssl_sites

build: all

test:
	./ssl_sites

ssl_sites: ssl_sites.ml
	ocamlfind ocamlc -custom -o ssl_sites -g -package netclient,nettls-gnutls -linkpkg ssl_sites.ml

.PHONY: clean
clean:
	rm -f *.cmi *.cmo *.cma *.o *.cmx *.a *.cmxa *.run
	rm -f ssl_sites
