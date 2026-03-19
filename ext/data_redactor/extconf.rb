require "mkmf"

abort "Missing C compiler or stdio.h" unless have_header("stdio.h")
abort "Missing regex.h"               unless have_header("regex.h")
abort "Missing stdlib.h"              unless have_header("stdlib.h")
abort "Missing string.h"              unless have_header("string.h")

create_makefile("data_redactor/data_redactor")
