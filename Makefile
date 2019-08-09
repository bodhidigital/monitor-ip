# Makefile

CFLAGS := \
	-std=c99 \
	-I/usr/include/ -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include \
	-lglib-2.0 \
	-Wall -Wextra -Werror -Wno-long-long -Wno-variadic-macros \
	$(CFLAGS)

default:
	gcc main.c $(CFLAGS) -o monitor-ip
