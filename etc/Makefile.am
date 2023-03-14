EXTRA_DIST = commands-samana6.cfg role-samana6-windows.cfg

TEMPLATE_DIR =  $(DESTDIR)${sysconfdir}/objects/samana
install:
	if [ ! -d $(TEMPLATE_DIR) ] ; then mkdir -p $(TEMPLATE_DIR) ; fi
	$(INSTALL) $(INSTALL_OPTS) -m 0664 commands-samana6.cfg $(TEMPLATE_DIR)/commands-samana6.cfg
	$(INSTALL) $(INSTALL_OPTS) -m 0664 role-samana6-windows.cfg $(TEMPLATE_DIR)/role-samana6-windows.cfg
