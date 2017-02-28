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

.PHONY: build
build: all
	if ocamlopt 2>/dev/null; then $(MAKE) opt; fi

.PHONY: all
all: tools
	for pkg in $(PKGLIST); do \
		( cd src/$$pkg && $(MAKE) -f Makefile.pre generate ) || exit; \
		( cd src/$$pkg && $(MAKE) -f Makefile.pre depend ) || exit; \
		( cd src/$$pkg && $(MAKE) all ) || exit; \
	done

.PHONY: opt
opt: tools
	for pkg in $(PKGLIST); do \
		( cd src/$$pkg && $(MAKE) -f Makefile.pre generate ) || exit; \
		( cd src/$$pkg && $(MAKE) -f Makefile.pre depend ) || exit; \
		( cd src/$$pkg && $(MAKE) opt ) || exit; \
	done


.PHONY: doc
doc:
	for pkg in src/*/.; do \
	    test ! -f $$pkg/Makefile -o -f $$pkg/doc-ignore || \
		{ ( cd $$pkg && $(MAKE) -f Makefile.pre generate ) || exit; \
		  ( cd $$pkg && $(MAKE) -f Makefile.pre depend ) || exit; \
		  ( cd $$pkg && $(MAKE) doc-dump ) || exit; \
		}; \
	done
	cd doc; $(MAKE) doc

.PHONY: tools
tools:
	( cd tools/cppo-$(CPPO_VERSION) && rm -f depend && $(MAKE) -f Makefile.pre generate && $(MAKE) all )
	( cd tools/unimap_to_ocaml && $(MAKE) all )


# The following PHONY rule is important for Cygwin:
.PHONY: install
install:
	for pkg in $(PKGLIST); do \
		( cd src/$$pkg && $(MAKE) -f Makefile.pre install ) || exit; \
	done

.PHONY: uninstall
uninstall:
	for pkg in src/*/.; do \
		test ! -f $$pkg/Makefile || \
			( cd $$pkg && $(MAKE) -f Makefile.pre uninstall); \
	done

.PHONY: clean
clean:
	for pkg in src/*/.; do \
		test ! -f $$pkg/Makefile || \
			( cd $$pkg && $(MAKE) -f Makefile.pre clean); \
	done
	if test -f doc/Makefile; then cd doc && $(MAKE) clean; fi
	( cd tools/cppo-$(CPPO_VERSION) && $(MAKE) clean )
	( cd tools/unimap_to_ocaml && $(MAKE) clean )

.PHONY: clean-doc
clean-doc:
	for pkg in src/*/.; do \
		test ! -f $$pkg/Makefile -o -f $$pkg/doc-ignore || \
			( cd $$pkg && $(MAKE) -f Makefile.pre clean-doc); \
	done
	cd doc && $(MAKE) clean-doc

.PHONY: CLEAN
CLEAN: clean

.PHONY: distclean
distclean:
	rm -f Makefile.conf 
	rm -rf tmp
	for pkg in src/*/.; do \
		test ! -f $$pkg/Makefile || \
			( cd $$pkg && $(MAKE) -f Makefile.pre distclean); \
	done

# That one is for oasis

.PHONY: postconf
postconf:
	cat setup.save >>setup.data


# phony because VERSION may also change
.PHONY: _oasis
_oasis: _oasis.in
	v=`./configure -version`; sed -e 's/@VERSION@/'"$$v/" _oasis.in >_oasis
	oasis setup
