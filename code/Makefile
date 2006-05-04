# make all: compiles the configured packages with ocamlc
# make opt: compiles the configured packages with ocamlopt
# make install: installs the configured packages
# make clean: cleans everything up

# Inclusion of Makefile.conf may fail when cleaning up:
-include Makefile.conf

NAME=ocamlnet
TOP_DIR=.

# PKGLIST: should be set in Makefile.conf. It contains the packages to
# compile and to install. The following assignment sets it to its 
# default value if no Makefile.conf exists.
PKGLIST ?= netstring cgi

.PHONY: all
all:
	#$(MAKE) -C tools all
	for pkg in $(PKGLIST); do ( cd src/$$pkg && $(MAKE) all ) || exit; done

.PHONY: opt
opt:
	for pkg in $(PKGLIST); do ( cd src/$$pkg && $(MAKE) opt ) || exit; done

# The following PHONY rule is important for Cygwin:
.PHONY: install
install:
	for pkg in $(PKGLIST); do ( cd src/$$pkg && $(MAKE) install ) || exit; done

.PHONY: uninstall
uninstall:
	for pkg in src/*/.; do test ! -f $$pkg/Makefile || ( cd $$pkg && $(MAKE) uninstall) ; done

.PHONY: clean
clean:
	#rm -f Makefile.conf
	#$(MAKE) -C tools CLEAN
	for pkg in src/*/.; do test ! -f $$pkg/Makefile || ( cd $$pkg && $(MAKE) clean) ; done

.PHONY: CLEAN
CLEAN: clean

.PHONY: distclean
distclean:
	rm -f Makefile.conf
	#$(MAKE) -C tools distclean
	for pkg in src/*/.; do test ! -f $$pkg/Makefile || ( cd $$pkg && $(MAKE) distclean) ; done