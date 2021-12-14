AC_INIT([inetmon], [1.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC_STDC

PKG_CHECK_MODULES([GLIB],[glib-2.0])
PKG_CHECK_MODULES([PCAP], [libpcap >= 1.9.1])
PKG_CHECK_MODULES([NCURSES],[ncurses])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
