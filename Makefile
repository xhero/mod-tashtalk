KPATH := /usr/src/linux-headers-`uname -r`
#KPATH := /home/ubuntu/linux-5.19

obj-m := ./src/hello.o

.PHONY: all clean doc

all:
	make -C $(KPATH) M=$(CURDIR) modules

clean:
	make -C $(KPATH) M=$(CURDIR) clean
	rm -rf ./doc

doc:
	doxygen ./Doxyfile
