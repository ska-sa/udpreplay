AC_INIT([udpreplay], [1.0])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CXX
AC_LANG(C++)

# Check for program_options
AC_CHECK_HEADER([boost/program_options.hpp], [], [AC_MSG_FAILURE([boost/program_options.hpp not found])])
AC_MSG_CHECKING([for boost_program_options library])
SAVED_LIBS="$LIBS"
LIBS="-lboost_program_options $LIBS"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <boost/program_options.hpp>]],
                     [[boost::program_options::option_description foo;]])],
    [AC_MSG_RESULT(yes)],
    [AC_MSG_RESULT(no)
     AC_MSG_FAILURE([boost_program_options library not found])])
LIBS="$SAVED_LIBS"

# Check for asio
AC_CHECK_HEADER([boost/asio.hpp], [], [AC_MSG_FAILURE([boost/asio.hpp not found])])
AC_MSG_CHECKING([for boost_system library])
SAVED_LIBS="$LIBS"
LIBS="-lboost_system $LIBS"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <boost/system/system_error.hpp>]],
                     [[boost::system::error_code ec;]])],
    [AC_MSG_RESULT(yes)],
    [AC_MSG_RESULT(no)
     AC_MSG_FAILURE([boost_system library not found])])

# Check for pcap
AC_CHECK_HEADER([pcap/pcap.h], [], [AC_MSG_FAILURE([pcap/pcap.h not found])])
AC_CHECK_LIB([pcap], [pcap_fopen_offline], [], [AC_MSG_FAILURE([pcap library not found])])

# Check for optional features
AC_CHECK_FUNCS([sendmmsg])
have_ibv=1
AC_CHECK_LIB([ibverbs], [ibv_create_flow], [], [have_ibv=0])
AC_CHECK_LIB([rdmacm], [rdma_create_id], [], [have_ibv=0])
AC_DEFINE_UNQUOTED([HAVE_IBV], [$have_ibv], [Whether ibverbs API should be supported])

# Report results
have_ibv_yesno=yes
if test "$have_ibv" = "0"
then
    have_ibv_yesno=no
fi
AC_MSG_NOTICE([[

The following optional features will be included:

    sendmmsg: $ac_cv_func_sendmmsg
    ibverbs:  $have_ibv_yesno
]])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
