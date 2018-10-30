SOCK_PATH := -DUNIX_SOCK_PATH=\('"/var/run/covert_module_tls"'\) -DSHELL_SOCK_PATH=\('"/var/run/remote_shell"'\)

BASEFLAGS := -Wall -Wextra -pedantic -pipe -std=c11 $(SOCK_PATH)
DEBUGFLAGS := -g -O0
RELEASEFLAGS := -s -O3 -march=native -flto -DNDEBUG
LIBFLAGS := -lcrypto -lssl

ccflags-y := $(SOCK_PATH)

obj-m += covert_module.o

all debug release: userspace.o server.o user.o
	$(CC) $(CUSTOM_CFLAGS) userspace.o user.o $(LIBFLAGS) -o userspace.elf
	$(CC) $(CUSTOM_CFLAGS) server.o user.o $(LIBFLAGS) -o server.elf
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Prevent clean from trying to do anything with a file called clean
.PHONY: clean

clean:
	$(RM) $(wildcard *.gch) userspace.o server.o covert_module.o user.o userspace.elf server.elf
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#Check if in debug mode and set the appropriate compile flags
ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(DEBUGFLAGS))
endif

%.o: %.c
	$(CC) $(CUSTOM_CFLAGS) -c $<
