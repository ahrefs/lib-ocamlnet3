TOP_DIR=../..

include $(TOP_DIR)/Makefile.conf

PKGNAME = netclient
OBJECTS =  nethttp_client_conncache.cmo nethttp_client.cmo nettelnet_client.cmo \
	   netftp_data_endpoint.cmo netftp_client.cmo \
	   nethttp_fs.cmo netftp_fs.cmo netsmtp.cmo netpop.cmo \
	   netldap.cmo
DOBJECTS = nethttp_client_conncache.mli nethttp_client.mli nettelnet_client.mli \
	   netftp_data_endpoint.mli netftp_client.mli \
	   nethttp_fs.mli netftp_fs.mli netsmtp.mli netpop.mli netldap.mli \
           netclient_tut.txt

OCAMLC_OPTIONS += $(STRING_OPTS)
OCAMLOPT_OPTIONS += $(STRING_OPTS)

PP_OPTIONS = -pp "$(CPPO) $(PP_BYTES) $(PP_DEPRECATED)"


INCLUDES = $(INC_EQUEUE) $(INC_NETSTRING) $(INC_NETSYS)

include $(TOP_DIR)/Makefile.rules

include depend
