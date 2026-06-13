require "mkmf"

abort "Missing C compiler or stdio.h" unless have_header("stdio.h")
abort "Missing regex.h"               unless have_header("regex.h")
abort "Missing stdlib.h"              unless have_header("stdlib.h")
abort "Missing string.h"              unless have_header("string.h")
abort "Missing pthread.h"             unless have_header("pthread.h")

# pthread_mutex_* needs -lpthread on glibc; on musl and macOS it lives in libc
# and have_library is a harmless no-op.
have_library("pthread")

# Compile every .c file in this directory. Order doesn't matter; mkmf
# generates per-object rules.
$srcs = Dir.glob("#{__dir__}/*.c").map { |f| File.basename(f) }

create_makefile("data_redactor/data_redactor")
