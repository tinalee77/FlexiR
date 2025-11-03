obj-m := tcp_flexir.o
IDIR= /lib/modules/$(shell uname -r)/kernel/net/ipv4/
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	install -v -m 644 tcp_flexir.ko $(IDIR)
	# use depmod when the module uses symbols exported by other modules or other modules use symbols exported by it
	# depmod analyzes the interdependencies for each kernel module and save the results to /usr/lib/modules/(uname -r)/modules.dep
	# so even if the module has dependencies, we only need to run depmod when the dependencies change
	#
	#depmod  
	modprobe tcp_flexir
	
uninstall:
	modprobe -r tcp_flexir
	
clean:
	rm -rf Module.markers modules.order Module.symvers tcp_flexir.ko tcp_flexir.mod.c tcp_flexir.mod.o tcp_flexir.o tcp_flexir.mod tcp_flexir.dwo tcp_flexir.mod.dwo
