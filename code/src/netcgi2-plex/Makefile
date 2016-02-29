TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = netcgi2-plex
OBJECTS  = netcgi_plex.cmo
DOBJECTS = netcgi_plex.mli

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

INCLUDES += -I ../netcgi2 -I ../netplex -I ../netsys

include $(TOP_DIR)/Makefile.rules

include depend
