CFLAGS  := -g
LDFLAGS := -lpam

default: auth
auth: auth.o

setuid: auth
	sudo chown root:root auth
	sudo chmod +s auth
