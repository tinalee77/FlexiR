# FlexiR
A receiver side less than best effort congestion control algorithm. The code was only tested on Ubuntu kernels up to version 6.9

Steps to compile and install FlexiR
1. Download the source code of Linux kernel
2. Patch the kernel using the the patches contained in the files provided in the repository rLEB-kernel-patch. All patches have the comment "RLBE CCA support"
3. Recompile and reinstall Linux Kernel and then reboot
4. Download tcp_flexir.c and Makefile to a folder of your choice, say, flexir
5. under the folder "flexir" type: make, then type: sudo make install
6. enter: lsmod | grep tcp, if you can see "tcp_flexir" in the results, congrats, FlexiR is ready to use.

How to use FlexiR
FlexiR can be enabled in an application using setsockopt as follows (example code is in C)
At any time when you want to make a connection less than best effort, you can insert the following code
char *name="flexir";
setsockopt(sd, SOL_TCP, TCP_RCV_CC, name, strlen(name));
   
