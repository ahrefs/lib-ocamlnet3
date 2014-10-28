#define _GNU_SOURCE
#define _ATFILE_SOURCE

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "caml/mlvalues.h"
#include "caml/alloc.h"

/* reminder: we return the exit code, and 0 means success */

value check(value dummy) {
    int fd1;
    int code;

    fd1 = open(".", O_RDONLY, 0);
    if (fd1 == -1) return Val_int(1);
    code = mkfifoat(fd1, "mkfifoat_test", 0666);
    if (code == -1) {
        if (errno == ENOSYS) return Val_int(1);
    }
    return Val_int(0);
}
