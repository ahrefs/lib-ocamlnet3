TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME  = netcgi
OBJECTS  = netcgi_common.cmo netcgi.cmo \
	netcgi_ajp.cmo netcgi_scgi.cmo netcgi_cgi.cmo \
	netcgi_fcgi.cmo  netcgi_dbi.cmo \
	netcgi1_compat.cmo \
	netcgi_test.cmo

DOBJECTS = netcgi_common.mli netcgi.mli \
	netcgi_ajp.mli netcgi_scgi.mli netcgi_cgi.mli \
	netcgi_fcgi.mli  netcgi_dbi.mli \
	netcgi1_compat.mli \
	netcgi_test.mli \
	netcgi_porting.txt

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"

INCLUDES += $(INC_NETSTRING) $(INC_NETSYS)

include $(TOP_DIR)/Makefile.rules

include depend
