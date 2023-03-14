EXTRA_DIST = configuressl.sh makedeb.sh

install-data:
	./configuressl.sh

rules: rules.template
	sed -e "s@%prefix%@$(prefix)@" \
		-e "s@%sysconfdir%@$(sysconfdir)@" \
		-e "s@%libexecdir%@$(libexecdir)@" \
		-e "s@%np_path%@$(np_path)@" $< > $@

clean:
	rm -f rules
