lib_LTLIBRARIES = libnfsclient-async.la

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/nfsc \
	-I$(abs_top_srcdir)/include/win32 \
	-I$(abs_top_srcdir)/mount \
	-I$(abs_top_srcdir)/nfs \
	-I$(abs_top_srcdir)/nfs4 \
	-I$(abs_top_srcdir)/portmap \
	-I$(abs_top_srcdir)/rquota \
	-I/home/taras/fio \
	-D_GNU_SOURCE -DCONFIG_STRSEP \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libnfs.la -lpopt
libnfsclient_async_la_LIBADD = $(COMMON_LIBS)
libnfsclient_async_la_SOURCES = nfsclient-async.c
libnfsclient_async_la_LDFLAGS = -shared -rdynamic -fPIC 