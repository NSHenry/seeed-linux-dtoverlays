KVERSION ?= $(shell uname -r)

obj-m += rs485-autoflow.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean