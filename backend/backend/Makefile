obj-m := mycache.o
mycache-objs := backend.o tmem.o
default:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
