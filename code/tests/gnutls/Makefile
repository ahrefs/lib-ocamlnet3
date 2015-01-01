all: test_client

.PHONY: all clean

test_client: test_client.ml
	ocamlfind ocamlc -package nettls-gnutls -linkpkg -custom -g \
		test_client.ml \
		-o test_client

crypto: crypto.ml
	ocamlfind ocamlc -package nettls-gnutls -linkpkg -custom -g \
		crypto.ml \
		-o crypto


clean:
	rm -f *.cmi *.cmo *.cmx *.o
	rm -f test_client crypto
	rm -rf certs
