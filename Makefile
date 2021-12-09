VERSION=linux-5.14
TGZ=${VERSION}.tar.gz
KSRCURL=https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/${TGZ}
VERSION_INSTALLED=.${VERSION}_installed
ARCH=x86
# -no-integrated-cpp
CPPFLAGS=-nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -fmacro-prefix-map=./{$VERSION}/= -Wall -Wundef  -I${VERSION}/arch/${ARCH}/include -I${VERSION}/arch/${ARCH}/include/generated  -I${VERSION}/include -I${VERSION}/arch/${ARCH}/include/uapi -I${VERSION}/arch/${ARCH}/include/generated/uapi -I${VERSION}/include/uapi -I${VERSION}/include/generated/uapi -include ${VERSION}/include/linux/compiler-version.h -include ${VERSION}/include/linux/kconfig.h -include ${VERSION}/include/linux/compiler_types.h -D__KERNEL__ -DKBUILD_MODFILE='"drivers/net/virtio_net"' -DKBUILD_BASENAME='"virtio_net"' -DKBUILD_MODNAME='"virtio_net"' -D__KBUILD_MODNAME=kmod_virtio_net
JACFLAGS=-Wno-unused-variable
CFLAGS=-Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu89 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 --param=allow-store-data-races=0 -Wframe-larger-than=2048 -fstack-protector-strong -Wimplicit-fallthrough=5 -Wno-unused-but-set-variable -Wno-unused-const-variable -fomit-frame-pointer -fno-stack-clash-protection -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-stringop-truncation -Wno-array-bounds -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned  -c 
.PHONEY: clean dist-clean

all: ${VERSION_INSTALLED} myvirtnet.c.i

#  gcc -Wp,-MMD,drivers/net/.virtio_net.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -fmacro-prefix-map=./= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu89 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 --param=allow-store-data-races=0 -Wframe-larger-than=2048 -fstack-protector-strong -Wimplicit-fallthrough=5 -Wno-unused-but-set-variable -Wno-unused-const-variable -fomit-frame-pointer -fno-stack-clash-protection -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-stringop-truncation -Wno-array-bounds -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned    -DKBUILD_MODFILE='"drivers/net/virtio_net"' -DKBUILD_BASENAME='"virtio_net"' -DKBUILD_MODNAME='"virtio_net"' -D__KBUILD_MODNAME=kmod_virtio_net -c -o drivers/net/virtio_net.o drivers/net/virtio_net.c

myvirtnet.c.i: myvirtnet.c
	gcc -E ${CPPFLAGS} $< > $@

myvirtnet.o: myvirtnet.c.i
	gcc ${CFLAGS} ${JACFLAGS} -no-integrated-cpp $< -o $@

virtio_net.c: ${VERSION}/drivers/net/virtio_net.c
	cp $< $@

virtio_net.c.i: virtio_net.c
	gcc -E ${CPPFLAGS} $< > $@

virtio_net.o: virtio_net.c.i
	gcc ${CFLAGS} ${JACFLAGS} -no-integrated-cpp $< -o $@

sym_virtio_net.c: virtio_net.c 
	cp virtio_net.c $@
	patch sym_virtio_net.c < sym_virtio_net.patch

sym_virtio_net.c.i: sym_virtio_net.c
	gcc -E ${CPPFLAGS} $< > $@

sym_virtio_net.o: sym_virtio_net.c.i
	gcc ${CFLAGS} ${JACFLAGS} -no-integrated-cpp $< -o $@

sym_virtio_net.patch: virtio_net.c sym_virtio_net.c
	diff -u virtio_net.c sym_virtio_net.c >$@; [ $$? -eq 1 ]

${TGZ}:
	wget ${KSRCURL}

${VERSION_INSTALLED}: ${TGZ}
	tar -zxf ${TGZ}
	touch ${VERSION_INSTALLED}

clean:
	-rm -rf $(wildcard *.i virtio_net.c)

dist-clean:
	-rm -rf $(wildcard ${VERSION_INSTALLED} ${VERSION} ${TGZ}  *~ )
