SUBDIRS = scripts src etc
NP_PATH=@np_path@

dist_doc_DATA = README.md
DIST='@dist_type@'
NAGIOS_USER=@nagios_user@
NAGIOS_GRP=@nagios_grp@
VERSION=@VERSION@
export DEBEMAIL=info@samanagroup.com

install-groups-users:
	@autoconf-macros/add_group_user $(DIST) $(NAGIOS_USER) $(NAGIOS_GRP) 1

deb:
	$(MAKE) dist
	$(MAKE) -C scripts rules
	mkdir -p deb
	mv $(distdir).tar.gz deb/
	cd deb; tar -xzvf $(distdir).tar.gz
	cd deb/$(distdir); debmake
	cp scripts/configuressl.sh deb/$(distdir)/debian/postinst
	cat scripts/rules >> deb/$(distdir)/debian/rules
	sed -i -e "s/^\(Depends.*\)/\1, gss-ntlmssp (>= 0.7.0)/" deb/$(distdir)/debian/control
	cd deb/$(distdir); debuild
	cp deb/*.deb .

clean-deb:
	rm -Rf deb
