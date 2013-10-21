all: test_client

.PHONY: all clean

test_client: test_client.ml
	ocamlfind ocamlc -package nettls-gnutls -linkpkg -custom -g \
		test_client.ml \
		-o test_client


clean:
	rm -f *.cmi *.cmo *.cmx *.o
	rm -f test_client
	rm -rf certs
