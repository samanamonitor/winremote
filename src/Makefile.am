SUBDIRS = lib

AM_CFLAGS = -I/usr/include/libxml2 \
	-I./lib

DEFS = -DLOCALEDIR=\"$(localedir)\"

LDADD=lib/libwinremote.a \
	$(NP_PATH)/plugins/libnpcommon.a \
	$(NP_PATH)/lib/libnagiosplug.a \
	$(NP_PATH)/gl/libgnu.a

libexec_PROGRAMS = check_wr_cpu check_wr_mem \
	check_wr_disk check_wr_log check_wr_pf \
	check_wr_uptime check_wr_service

EXTRA_PROGRAMS = wr-get-schema wr-enumerate