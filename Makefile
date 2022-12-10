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

clean:
	rm -f $(TARGETS) *.o *.pdf *.bin *.com *.zip *.out *.txt


# Monitor

Z80Monitor-586.bin:
	wget https://raw.githubusercontent.com/lkundrak/Z80SerialMonitor-586/82b2a3ae400/$@

mon: Z80Monitor-586.bin runz80
	./runz80 --raw Z80Monitor-586.bin


# Yaze test suite

YAZETESTS = prelim sys zexall savage timex zexdoc

%.txt: %.com runz80
	./runz80 --cpm $<

$(addsuffix .com,$(YAZETESTS)):
	wget https://raw.githubusercontent.com/begoon/yaze/4424f29172/test/$@

yaze-test: $(addsuffix .txt,$(YAZETESTS))


# z80test test suite

Z80TESTS = z80ccf z80doc z80docflags
Z80TESTS += z80flags z80full z80memptr
#Z80TESTS += z80ccfscr

z80test-1.2.zip:
	wget https://github.com/raxoft/z80test/releases/download/v1.2/$@

$(addsuffix .out,$(Z80TESTS)): z80test-1.2.zip
	unzip -p $< z80test-1.2/$(basename $@).tap |dd bs=91 skip=1 of=$@

%.txt: %.out runz80
	./runz80 --zx $< |tee $@

test: $(addsuffix .txt,$(Z80TESTS))


# Quick smoke test

smoke: runz80 prelim.com z80doc.out
	./runz80 --cpm prelim.com
	./runz80 --zx z80doc.out
