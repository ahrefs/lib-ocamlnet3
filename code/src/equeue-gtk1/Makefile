TOP_DIR=../..

include ./Makefile.gtk
# Sets GTK_PKG, GTK_VERSION, ARCHIVE, FL_NAME

PKGNAME = $(FL_NAME)
OBJECTS = uq_gtk_helper.cmo uq_gtk.cmo
DOBJECTS = uq_gtk.mli

INCLUDES += $(INC_EQUEUE)
INCLUDES += $(INC_NETSYS)

PP_OPTIONS = -pp "$(CPPO) $(GTK_DEFINES)"

NODEP = @true

include $(TOP_DIR)/Makefile.rules

REQUIRES += $(GTK_PKG)
GTK_DEFINES += -D $(GTK_VERSION)

# Manual deps so we don't need ocamldep:
uq_gtk.cmo: uq_gtk_helper.cmo
uq_gtk.cmo: uq_gtk.cmi
uq_gtk.cmx: uq_gtk_helper.cmx
uq_gtk.cmx: uq_gtk.cmi
