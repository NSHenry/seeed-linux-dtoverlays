#
# Ruiqian Tang <tangruiqian17@gmail.com>
# Copyright (c) 2024 Seeed Studio
#
# MIT License
#
KVERSION ?= $(shell uname -r)

obj-m += gpio-beeper.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
