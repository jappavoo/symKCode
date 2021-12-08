VERSION=linux-5.14
TGZ=${VERSION}.tar.gz
KSRCURL=https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/${TGZ}
VERSION_INSTALLED=.${VERSION}_installed
ARCH=x86

.PHONEY: clean dist-clean

all: ${VERSION_INSTALLED} myvirtnet.c.i

myvirtnet.c.i: myvirtnet.c
	gcc -E -I${VERSION}/include -I${VERSION}/arch/${ARCH}/include -Iinclude  $< > $@

${TGZ}:
	wget ${KSRCURL}

${VERSION_INSTALLED}: ${TGZ}
	tar -zxf ${TGZ}
	touch ${VERSION_INSTALLED}

clean:
	-rm -rf $(wildcard *.i)

dist-clean:
	-rm -rf $(wildcard ${VERSION_INSTALLED} ${VERSION} ${TGZ})
