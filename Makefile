TARGETS = disz80 disz80.1
TARGETS += runz80 runz80.1

DOCS = disz80.pdf runz80.pdf

# Defaults I use.
# Override with something better if you think you're smart.
CFLAGS = -g3 -O2 -Wall -Werror

all: $(TARGETS)

docs: $(DOCS)

z80-print.o: z80.c z80.h
	$(CC) $(CFLAGS) -c -o $@ -DZ80_NO_EXEC $<

z80.o disz80.o runz80.o: z80.h
runz80: z80.o
disz80: z80-print.o

%.1: %.pod
	pod2man --center 'Development Tools' \
		--section 1 --date 2022-12-11 --release 2 $< >$@

%.pdf: %.1
	groff -Tpdf -mman $< >$@

.PHONY: test
test: prelim.com runz80
	./runz80 prelim.com

mon: Z80Monitor-586.bin runz80
	./runz80 Z80Monitor-586.bin

Z80Monitor-586.bin:
	wget https://raw.githubusercontent.com/lkundrak/Z80SerialMonitor-586/82b2a3ae400/$@

prelim.com:
	wget https://raw.githubusercontent.com/begoon/yaze/4424f29172/test/$@

clean:
	rm -f $(TARGETS) *.o *.pdf Z80Monitor-586.bin prelim.com

