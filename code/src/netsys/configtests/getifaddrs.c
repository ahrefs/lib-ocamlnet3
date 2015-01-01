#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include "caml/mlvalues.h"
#include "caml/alloc.h"

/* reminder: we return the exit code, and 0 means success */

value check(value dummy) {
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return Val_int(1);
    }
    return Val_int(0);
}
