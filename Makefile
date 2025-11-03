obj-m := tcp_flexir.o
IDIR= /lib/modules/$(shell uname -r)/kernel/net/ipv4/
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	install -v -m 644 tcp_flexir.ko $(IDIR)
	depmod  
	modprobe tcp_flexir
	
uninstall:
	modprobe -r tcp_flexir
	
clean:
	rm -rf Module.markers modules.order Module.symvers tcp_flexir.ko tcp_flexir.mod.c tcp_flexir.mod.o tcp_flexir.o tcp_flexir.mod tcp_flexir.dwo tcp_flexir.mod.dwo
