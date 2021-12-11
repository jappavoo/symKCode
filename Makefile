VERSION=linux-5.14
TGZ=${VERSION}.tar.gz
KSRCURL=https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/${TGZ}
VERSION_INSTALLED=.${VERSION}_installed
ARCH=x86
# -no-integrated-cpp
CPPFLAGS=-nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -fmacro-prefix-map=./{$VERSION}/= -Wall -Wundef  -I${VERSION}/arch/${ARCH}/include -I${VERSION}/arch/${ARCH}/include/generated  -I${VERSION}/include -I${VERSION}/arch/${ARCH}/include/uapi -I${VERSION}/arch/${ARCH}/include/generated/uapi -I${VERSION}/include/uapi -I${VERSION}/include/generated/uapi -include ${VERSION}/include/linux/compiler-version.h -include ${VERSION}/include/linux/kconfig.h -include ${VERSION}/include/linux/compiler_types.h -D__KERNEL__ -DKBUILD_MODFILE='"drivers/net/virtio_net"' -DKBUILD_BASENAME='"virtio_net"' -DKBUILD_MODNAME='"virtio_net"' -D__KBUILD_MODNAME=kmod_virtio_net
JACFLAGS=-Wno-unused-variable
#PICFLAG=-fno-PIE 
CFLAGS=-Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar ${PICFLAG} -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu89 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 --param=allow-store-data-races=0 -Wframe-larger-than=2048 -fstack-protector-strong -Wimplicit-fallthrough=5 -Wno-unused-but-set-variable -Wno-unused-const-variable -fomit-frame-pointer -fno-stack-clash-protection -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-stringop-truncation -Wno-array-bounds -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned  -c 

LINE=1545
FILE=virtio_net.c
VMLINUX=linux-5.14/vmlinux

.PHONEY: clean dist-clean all download extract config prepare 

all: old.dump new.dump myvirt virtnet symvirt lkvirt 

new.o: new.S
	gcc -c new.S -o new.o

new.opcodes: new.o
	./bin/getOpcodes $< 0: > $@

new.xxd: new.opcodes
	cut -f 2 $< > $@

new.bin: new.xxd
	xxd -ps -r $< > $@

new.dump: new.bin old.addr
	ndisasm -o 0x$(shell cat old.addr) -b 64 -p intel $< > $@

#opcodes:
#	./ifopcodes > opcodes


old.addr: 
	./bin/getLineAddr ${VMLINUX} ${FILE} ${LINE} > $@
#	head -1 $<  | cut -f 1  -d ':' > $@

old.opcodes: old.addr
	./bin/getOpcodes ${VMLINUX} $(shell cat old.addr) > $@

old.xxd: old.opcodes
	cut -f 2 $< > $@

old.bin: old.xxd
	xxd -ps -r $< > $@

old.dump: old.bin old.addr
	ndisasm -o 0x$(shell cat old.addr) -b 64 -p intel $< > $@

main.o: main.c
	gcc $< -c -o $@

myvirt: main.o myvirtnet.o 
	gcc -o $@ $^

virtnet: main.o virtio_net.o
	gcc -o $@ $^

symvirt: main.o sym_virtio_net.o
	gcc -o $@ $^

lkvirt: main.o ${VERSION}/drivers/net/virtio_net.o
	gcc -o $@ $^


#  gcc -Wp,-MMD,drivers/net/.virtio_net.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -fmacro-prefix-map=./= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu89 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 --param=allow-store-data-races=0 -Wframe-larger-than=2048 -fstack-protector-strong -Wimplicit-fallthrough=5 -Wno-unused-but-set-variable -Wno-unused-const-variable -fomit-frame-pointer -fno-stack-clash-protection -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-stringop-truncation -Wno-array-bounds -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned    -DKBUILD_MODFILE='"drivers/net/virtio_net"' -DKBUILD_BASENAME='"virtio_net"' -DKBUILD_MODNAME='"virtio_net"' -D__KBUILD_MODNAME=kmod_virtio_net -c -o drivers/net/virtio_net.o drivers/net/virtio_net.c


myvirtnet.c.i: myvirtnet.c prepare
	gcc -E ${CPPFLAGS} $< > $@

myvirtnet.o: myvirtnet.c.i
	gcc ${CFLAGS} ${JACFLAGS} -no-integrated-cpp $< -o $@

lk_build_cmd: ${VERSION}/drivers/net/virtio_net.o

${VERSION}/drivers/net/virtio_net.o: prepare
	make V=1 -C ${VERSION} drivers/net/virtio_net.o | grep -- '-o drivers/net/virtio_net.o' > lk_build_cmd

virtio_net.c: ${VERSION}/drivers/net/virtio_net.c
	cp $< $@

virtio_net.c.i: virtio_net.c
	gcc -E ${CPPFLAGS} $< > $@

virtio_net.o: virtio_net.c.i
	gcc ${CFLAGS} ${JACFLAGS} -no-integrated-cpp $< -o $@

sym_virtio_net.c: virtio_net.c 
	cp virtio_net.c $@
	patch sym_virtio_net.c < sym_virtio_net.patch

sym_virtio_net.c.i: sym_virtio_net.c prepare
	gcc -E ${CPPFLAGS} $< > $@

sym_virtio_net.o: sym_virtio_net.c.i
	gcc ${CFLAGS} ${JACFLAGS} -no-integrated-cpp $< -o $@

sym_virtio_net.patch: virtio_net.c sym_virtio_net.c
	diff -u virtio_net.c sym_virtio_net.c >$@; [ $$? -eq 1 ]


${TGZ}:
	wget ${KSRCURL}
download: ${TGZ}

${VERSION_INSTALLED}: ${TGZ}
	tar -zxf ${TGZ}
	touch ${VERSION_INSTALLED}
extract: ${VERSION_INSTALLED}

${VERSION}/.config:  defconfig_virtio ${VERSION_INSTALLED}
	cp $< $@
	make -C ${VERSION} oldconfig
config: ${VERSION}/.config

${VERSION}/arch/${ARCH}/include/generated/asm/rwonce.h: config
	make -C ${VERSION} prepare
prepare: ${VERSION}/arch/${ARCH}/include/generated/asm/rwonce.h

#$(VERSION}/include/arch/
clean:
	-rm -rf $(wildcard *.i *.o *.out *~ ${VERSION}/drivers/net/virtio_net.o virtio_net.c sym_virtio_net.c lk_build_cmd *.bin *.dump *.addr *.opcodes *.xxd)

dist-clean: clean
	-rm -rf $(wildcard ${VERSION_INSTALLED} ${VERSION} ${TGZ} )
