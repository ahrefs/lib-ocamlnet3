TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf
include Makefile.conf

PKGNAME  = netsys
OBJECTS  = netsys_conf.cmo netsys_types.cmo \
           netlog.cmo netexn.cmo netsys_impl_util.cmo netsys_mem.cmo \
	   netsys_signal.cmo netsys_crypto_types.cmo netsys_crypto.cmo \
	   netsys_crypto_modes.cmo \
	   netsys_posix.cmo netsys_win32.cmo netsys_tls.cmo netsys.cmo \
	   netsys_ciphers.cmo netsys_digests.cmo netsys_rng.cmo \
	   netsys_pollset.cmo netsys_pollset_posix.cmo \
	   netsys_pollset_win32.cmo netsys_pollset_generic.cmo \
	   netsys_xdr.cmo netsys_tmp.cmo \
	   netsys_sem.cmo netsys_pmanage.cmo netsys_global.cmo \
	   netsys_gssapi.cmo netsys_sasl_types.cmo netsys_sasl_util.cmo \
	   netsys_sasl.cmo netsys_polypipe.cmo netsys_polysocket.cmo
COBJECTS = netsys_c.o netsys_c_poll.o netsys_c_fadvise.o \
	   netsys_c_fallocate.o netsys_c_ioprio.o netsys_c_locale.o \
           netsys_c_multicast.o netsys_c_sem.o netsys_c_shm.o \
           netsys_c_spawn.o netsys_c_subprocess.o netsys_c_syslog.o \
	   netsys_c_clock.o netsys_c_event.o \
           netsys_c_win32.o netsys_c_htab.o netsys_c_queue.o \
           netsys_c_mem.o netsys_c_xdr.o netsys_c_ip6.o
DOBJECTS = netsys.mli netsys_posix.mli netsys_pollset.mli netlog.mli \
           netexn.mli netsys_win32.mli netsys_pollset_posix.mli \
           netsys_pollset_win32.mli netsys_pollset_generic.mli \
           netsys_signal.mli netsys_oothr.mli netsys_xdr.mli \
	   netsys_rng.mli netsys_crypto_types.mli \
	   netsys_types.mli netsys_mem.mli netsys_tmp.mli \
	   netsys_sem.mli netsys_pmanage.mli netsys_crypto.mli netsys_tls.mli \
	   netsys_ciphers.mli netsys_digests.mli netsys_crypto_modes.mli \
	   netsys_gssapi.mli netsys_sasl_types.mli netsys_sasl.mli \
	   netsys_polypipe.mli netsys_polysocket.mli netsys_global.mli
LINK_OPTIONS = $(NETSYS_LINK_OPTIONS)

ALL_EXTRA = netsys_oothr.cma $(OOH_OBJECT)
ALLMT_EXTRA = netsys_oothr_mt.cma netsys_oothr_mt_init.cmo
OPT_EXTRA = netsys_oothr.cmxa netsys_c_gprof.o $(OOH_OBJECT)
OPTP_EXTRA = netsys_oothr.p.cmxa netsys_gprof_init.cmx
OPTMT_EXTRA = netsys_oothr_mt.cmxa netsys_oothr_mt_init.cmx
OPTMTP_EXTRA = netsys_oothr_mt.p.cmxa netsys_oothr_mt_init.cmx
ifeq ($(HAVE_SHARED),1)
OPT_EXTRA += netsys_oothr.cmxs
OPTP_EXTRA += netsys_oothr.p.cmxs
OPTMT_EXTRA += netsys_oothr_mt.cmxs netsys_oothr_mt_init.cmxs
OPTMTP_EXTRA += netsys_oothr_mt.p.cmxs
endif
# Note: we cannot refer here to *.p.cmx because there is no direct
# rule to build these files from .ml. They are implicitly built
# when the corresponding *.cmx (without .p) is created.

OCAMLC_OPTIONS_FOR_netsys_oothr_mt.mli = $(THREAD)
OCAMLC_OPTIONS_FOR_netsys_oothr_mt.ml = $(THREAD)
OCAMLC_OPTIONS_FOR_netsys_oothr_mt_init.mli = $(THREAD)
OCAMLC_OPTIONS_FOR_netsys_oothr_mt_init.ml = $(THREAD)
OCAMLOPT_OPTIONS_FOR_netsys_oothr_mt.ml = $(THREAD)
OCAMLOPT_OPTIONS_FOR_netsys_oothr_mt_init.ml = $(THREAD)
OCAMLC_OPTIONS_FOR_netsys_c_xdr.c = -ccopt -O

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(DEF_O_SHARE_DELETE) $(DEF_O_CLOEXEC) $(DEF_O_KEEPEXEC) $(PP_BYTES) $(PP_DEPRECATED)"

INSTALL_EXTRA += netsys_c_event.h $(OOH_OBJECT)

include $(TOP_DIR)/Makefile.rules

netsys_types.ml: netsys_types.mli
	echo '(* WARNING! THIS IS A COPY OF NETSYS_TYPES.MLI! *)' \
	    >netsys_types.ml
	cat netsys_types.mli >> netsys_types.ml

netsys_types.cmo: netsys_types.cmi
netsys_types.cmx: netsys_types.cmi

CLEAN_LIST += netsys_types.ml

.PHONY: cobjects
cobjects: $(COBJECTS)

netsys_oothr.cma: netsys_oothr.cmo
	$(OCAMLC) -o netsys_oothr.cma -a netsys_oothr.cmo

netsys_oothr.cmxa: netsys_oothr.cmx
	$(OCAMLOPT) -o netsys_oothr.cmxa -a netsys_oothr.cmx

netsys_oothr.cmxs: netsys_oothr.cmxa
	$(OCAMLOPT) -linkall -shared -o netsys_oothr.cmxs netsys_oothr.cmxa

netsys_oothr.p.cmxa: netsys_oothr.cmx
	$(OCAMLOPT) -o netsys_oothr.p.cmxa -a netsys_oothr.p.cmx

netsys_oothr.p.cmxs: netsys_oothr.p.cmxa
	$(OCAMLOPT) -linkall -shared -o netsys_oothr.p.cmxs netsys_oothr.p.cmxa

netsys_oothr_mt.cma: netsys_oothr.cmo netsys_oothr_mt.cmo
	$(OCAMLC) -o netsys_oothr_mt.cma -a \
		netsys_oothr.cmo netsys_oothr_mt.cmo

netsys_oothr_mt.cmxa: netsys_oothr.cmx netsys_oothr-$(MT_TYPE)
	$(OCAMLOPT) -o netsys_oothr_mt.cmxa -a \
		netsys_oothr.cmx netsys_oothr_mt.cmx

netsys_oothr_mt.cmxs: netsys_oothr_mt.cmxa
	$(OCAMLOPT) -linkall -shared -o netsys_oothr_mt.cmxs netsys_oothr_mt.cmxa

netsys_oothr_mt_init.cmxs: netsys_oothr_mt_init.cmx
	$(OCAMLOPT) -linkall -shared -o netsys_oothr_mt_init.cmxs netsys_oothr_mt_init.cmx

netsys_oothr_mt.p.cmxa: netsys_oothr.cmx netsys_oothr-$(MT_TYPE)
	$(OCAMLOPT) -o netsys_oothr_mt.p.cmxa -a \
		netsys_oothr.p.cmx netsys_oothr_mt.p.cmx

netsys_oothr_mt.p.cmxs: netsys_oothr_mt.p.cmxa
	$(OCAMLOPT) -linkall -shared -o netsys_oothr_mt.p.cmxs \
		netsys_oothr_mt.p.cmxa

.PHONY: netsys_oothr-vm netsys_oothr-posix
netsys_oothr-vm:

netsys_oothr-posix: netsys_oothr_mt.cmx


clean::
	rm -f configtests/*.o configtests/*.err
	rm -f configtests/posix_shm

include depend
