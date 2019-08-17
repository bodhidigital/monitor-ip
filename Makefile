# Makefile

LDFLAGS := \
	$(shell pkgconf --libs glib-2.0) \
	$(LDFLAGS)
CFLAGS := \
	-std=c99 \
	$(shell pkgconf --cflags glib-2.0) \
	-Wall -Wextra -Werror -Wno-long-long -Wno-variadic-macros \
	$(CFLAGS)

CFLAGS_DEBUG =

executable := monitor-ip
objects := timeutil.o checksum.o packet.o record.o netio.o monitor.o log.o \
           main.o
headers := timeutil.h checksum.h packet.h record.h netio.h monitor.h log.h

.PHONY: all default debug
all: default ;
default: $(executable) ;
debug: $(executable) ;

.PHONY: clean
clean: clean-executable clean-objects ;

debug: CFLAGS_DEBUG += -ggdb -O0

$(executable): $(objects)
	gcc $^ $(LDFLAGS) -o $@

$(objects):%.o:%.c $(headers)
	gcc -c $(CFLAGS) $(CFLAGS_DEBUG) $< -o $@

.PHONY: clean-executable
clean-executable:
	if [ -f $(executable) ]; then \
	  rm -f -- $(executable); \
	fi

.PHONY: clean-objects
clean-objects:
	for object in $(objects); do \
	  if [ -f $$object ]; then \
	    rm -f -- $$object; \
	  fi; \
	done
