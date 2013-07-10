noinst_PROGRAMS = block_tcp

bin_PROGRAMS = block_tcp
block_tcp_SOURCES =  block_tcp.cpp
block_tcp_CXXFLAGS = $(libnetfilter_queue_CFLAGS) $(libnfnetlink_CFLAGS) -I../
block_tcp_LDADD =    $(libnetfilter_queue_LIBS) $(libnfnetlink_LIBS) $(PTHREAD_LIBS)

cleanall:
	rm -fr block_tcp block_tcp-block_tcp.o config.log Makefile Makefile Makefile.in missing aclocal.m4 configure config.status depcomp autom4te.cache

install-all: install
	cp start.sh $(DESTDIR)$(bindir)/start_btcp
	chmod +x $(DESTDIR)$(bindir)/start_btcp
	cp stop.sh $(DESTDIR)$(bindir)/stop_btcp
	chmod +x $(DESTDIR)$(bindir)/stop_btcp

remove-all: uninstall
	rm -f $(DESTDIR)$(bindir)/start_btcp
	rm -f $(DESTDIR)$(bindir)/stop_btcp
