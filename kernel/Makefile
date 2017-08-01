obj-m  := traffic-st.o 

KERNEL := /lib/modules/`uname -r`/build

all:
	make -C $(KERNEL)	M=`pwd` modules

install:
	make -C $(KERNEL)	M=`pwd` modules_install
	depond -A

clean:
	make -C $(KERNEL)   M=`pwd` clean

