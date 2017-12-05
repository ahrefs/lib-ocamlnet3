#! /bin/sh

set -e

cp files/ocamlnet.install .

cd code
./configure "$@"
make all
make opt

