run_proto: run_proto.ml
	ocamlfind ocamlc -custom -o run_proto -package netgss-system -linkpkg \
		run_proto.ml

.PHONY: clean
clean:
	rm -rf *.cmo *.cmi *.cmx *.o run_proto
