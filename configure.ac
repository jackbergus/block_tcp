AC_INIT([block_tcp], [0.1], [giacomo90@libero.it])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

#C++ with c++11 standard
AC_LANG([C++])
AX_CHECK_COMPILE_FLAG([-std=c++11], [CXXFLAGS="$CXXFLAGS -std=c++11"])


PKG_CHECK_MODULES(libnetfilter_queue, libnetfilter_queue >= 0.0.17 )
PKG_CHECK_MODULES(libnfnetlink, libnfnetlink >= 0.0.17 )

#Detect pthreads libraries
PTHREAD_LIBS=error
AC_CHECK_LIB(pthread, pthread_attr_init, PTHREAD_LIBS="-lpthread")
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(pthreads, pthread_attr_init, PTHREAD_LIBS="-lpthreads")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(c_r, pthread_attr_init, PTHREAD_LIBS="-lc_r")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_FUNC(pthread_attr_init, PTHREAD_LIBS="")
fi
AC_SUBST(PTHREAD_LIBS)






#Generating files

# Generating Static Libraries
AC_PROG_RANLIB

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
