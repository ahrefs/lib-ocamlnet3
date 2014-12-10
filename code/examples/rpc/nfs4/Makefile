TOP_DIR = ../../..
XDRFILES = rfc3530.x

RPCGEN_AUX_OPTIONS    = -D TRUE=1 -D FALSE=0 -D RPCSEC_GSS=6 \
	                -int int32 -hyper int64
RPCGEN_CLIENT_OPTIONS = $(RPCGEN_AUX_OPTIONS)
RPCGEN_SERVER_OPTIONS = $(RPCGEN_AUX_OPTIONS)

CLEAN_LIST += *.astamp *.cstamp *.s2stamp
CLEAN_LIST += $(XDRFILES:.x=_aux.ml) $(XDRFILES:.x=_aux.mli)
CLEAN_LIST += $(XDRFILES:.x=_clnt.ml) $(XDRFILES:.x=_clnt.mli)

include $(TOP_DIR)/Makefile.xrules

all:
	$(MAKE) gen
	$(MAKE) -f Makefile.code depend
	$(MAKE) -f Makefile.code all

opt:
	$(MAKE) gen
	$(MAKE) -f Makefile.code depend
	$(MAKE) -f Makefile.code opt

gen: $(XDRFILES:.x=.astamp) $(XDRFILES:.x=.cstamp)

clean:
	$(MAKE) -f Makefile.code clean
	rm -f $(CLEAN_LIST)
