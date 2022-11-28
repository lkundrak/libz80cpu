/*
 * Stupid Z80 processor emulator and disassembler.
 *
 * Don't use this, there are better tools for the job out there.
 * See <https://github.com/begoon/yaze> for example.
 *
 * Copyright (C) 2022  Lubomir Rintel <lkundrak@v3.sk>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "z80.h"

static int stopsim = 0;
static int dintm = 0;
static int debug_io = 0;
static int debug_z80 = 0;

/* These are configured to match
 * Z80SerialMonitor/CONSTANTS-F000-E0.asm */
#define ROM_BOTTOM	0xf000
#define UART_BASE	0xe0

/* For compatibility with Altos 586 IOP */
#define A586_ROM_BOTTOM	0x0000
#define A586_CTC0_BASE	0x20
#define A586_SIO0_BASE	0x2c

_Static_assert(A586_ROM_BOTTOM < ROM_BOTTOM);

static void
out (struct z80 *z, uint8_t addr, uint8_t val)
{
	stopsim = 1;

	if (addr != A586_CTC0_BASE + 1 && val != 0x00)
		dintm = 0;

	switch (addr) {
	case A586_CTC0_BASE + 2:
	case A586_CTC0_BASE + 3:
		/* Just ignore these. */
		stopsim = 0;
		break;
	case UART_BASE + 1:
	case A586_SIO0_BASE:
		/* Serial data. */
		if (val == '\r') {
			stopsim = 0;
			break;
		}
		switch (write (STDOUT_FILENO, &val, 1)) {
		case 1:
			stopsim = 0;
			break;
		case -1:
			perror("write");
		}
		break;
	case UART_BASE + 3:
	case A586_SIO0_BASE + 1:
		/* Serial control. Just ignore. */
		stopsim = 0;
		break;
	}

	if (debug_io || stopsim)
		fprintf(stderr, "OUT 0x%02x <- 0x%02x\n", addr, val);
	stopsim = 0;
}

static uint8_t
in (struct z80 *z, uint8_t addr)
{
	struct pollfd pfd = { STDIN_FILENO, POLLIN };
	int timeout = dintm;
	int val = 0x5a;

	stopsim = 1;
	dintm = 0;

	switch (addr) {
	case UART_BASE + 1:
	case A586_SIO0_BASE:
		/* Serial data. */
		switch (read (STDIN_FILENO, &val, 1)) {
		case -1:
			if (errno != EWOULDBLOCK)
				perror("read");
			break;
		case 1:
			stopsim = 0;
			break;
		}
		break;
	case UART_BASE + 3:
	case A586_SIO0_BASE + 1:
		/* Serial status. */
		stopsim = 0;
		val = 0x04; /* TX buffer empty */
		if (poll(&pfd, 1, timeout) == 1 && pfd.revents) {
			/* RX character available */
			val |= 0x01;
			stopsim = 0;
		} else {
			/* No data this time. Wait until next time,
			 * unless there's other i/o in between */
			dintm = -1;
		}
		break;
	}

	if (debug_io || stopsim)
		fprintf(stderr, "IN 0x%02x -> 0x%02x\n", addr, val);
	stopsim = 0;

	return val;
}

uint8_t mem[0x10000];

static uint8_t
wr (struct z80 *z, uint16_t addr, uint8_t val)
{
	if (debug_io)
		fprintf(stderr, "WR 0x%04x <- 0x%02x\n", addr, val);
	return mem[addr] = val;
}

static uint8_t
rd (struct z80 *z, uint16_t addr)
{
	uint8_t val = mem[addr];

	if (debug_io)
		fprintf(stderr, "RD 0x%04x -> 0x%02x\n", addr, val);
	return val;
}

struct termios orig_tio;

static int
setty(void)
{
        struct termios tio;

	if (tcgetattr(STDIN_FILENO, &orig_tio) == -1) {
		perror("tcgetattr");
		return -1;
	}

	tio = orig_tio;
	tio.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &tio) == -1) {
		perror("tcsetattr");
		return -1;
	}

	if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) == -1) {
		perror("F_SETFL");
		return -1;
	}

	return 0;
}

static void
cleantty(void)
{
	fflush(stdout);
	fflush(stderr);
	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &orig_tio) == -1)
		perror("cleantty: tcsetattr");
}

int
main (int argc, char *argv[])
{
	enum z80_flags flags = Z80_EXEC;
	struct z80 z = { 0, };
	uint8_t *p;
	int fd;
	int br;

	z.in = in;
	z.out = out;
	z.read = rd;
	z.write = wr;

	z.r16[AF] = 0xffff;
	z.r16[SP] = 0xffff;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <program>\n", argv[0]);
		return 1;
	}

	if (strlen(argv[1]) > 4 && strcmp(argv[1] + strlen(argv[1]) - 4, ".com") == 0) {
		/* Assume this is a CP/M program. These start at 0x100  */
		z.r16[PC] = 0x0100;

		/* Just halt on exit. */
		mem[0x0000] = 0x76; /* halt */

		/* Stub CP/M console system calls,
		 * just enough to get output from yaze
		 * test programs. */
		mem[0x0005] = 0x79; /*		ld a,c 			*/
		mem[0x0006] = 0x0e; /*		ld c,UART_BASE + 1 	*/
		mem[0x0007] = UART_BASE + 1;

		/* Check if it's call 2 (putchar) */
		mem[0x0008] = 0xfe; /*		cp 2 			*/
		mem[0x0009] = 0x02;
		mem[0x000a] = 0x20; /*		jr nz, n2 		*/
		mem[0x000b] = 0x03;

		/* It is. Send out the character and be done. */
		mem[0x000c] = 0xed; /*		out (c),e 		*/
		mem[0x000d] = 0x59;
		mem[0x000e] = 0xc9; /*		ret 			*/

		/* It's not 2. Check if it's 9 (puts) */
		mem[0x000f] = 0xfe; /*	n2:	cp 9 			*/
		mem[0x0010] = 0x09;
		mem[0x0011] = 0xc2; /*		jp nz, 0 		*/
		mem[0x0012] = 0x00;
		mem[0x0013] = 0x00;

		/* It is. Loop until we reach the terminating '$' */
		mem[0x0014] = 0x1a; /*	next:	ld a,(de) 		*/
		mem[0x0015] = 0xfe; /*		cp '$' 			*/
		mem[0x0016] = 0x24;
		mem[0x0017] = 0x28; /*		jr z,rt 		*/
		mem[0x0018] = 0x06;
		mem[0x0019] = 0xed; /*		out (c),a 		*/
		mem[0x001a] = 0x79;
		mem[0x001b] = 0x13; /*		inc de 		*/
		mem[0x001c] = 0xc3; /*		jp next 		*/
		mem[0x001d] = 0x14;
		mem[0x001e] = 0x00;

		/* Done. Terminate with a newline. */
		mem[0x001f] = 0x3e; /* rt:	ld a,0x0a 		*/
		mem[0x0020] = 0x0a;
		mem[0x0021] = 0xed; /*		out (c),a 		*/
		mem[0x0022] = 0x79;
		mem[0x0023] = 0xc9; /*		ret 		*/
	} else {
		/* A raw program. */
		z.r16[PC] = ROM_BOTTOM;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror(argv[1]);
		return 1;
	}
	p = &mem[z.r16[PC]];
	do {
		br = read (fd, p, &mem[sizeof(mem)] - p);
		if (br == -1) {
			perror(argv[1]);
			return 1;
		}
		p += br;
	} while (br);
	close (fd);

	if (mem[0x0000] != 0x76) {
		/* If not a .com file, relocate for Altos 586 IOP compatibility. */
		memcpy (&mem[A586_ROM_BOTTOM], &mem[ROM_BOTTOM], p - &mem[ROM_BOTTOM]);
	}

	if (setty())
		return 1;

	debug_io = !!getenv("DEBUG_IO");
	debug_z80 = !!getenv("DEBUG_Z80");

	if (debug_z80) {
		flags |= Z80_PRINT_REGS;
		flags |= Z80_PRINT_DATA;
		flags |= Z80_PRINT_INSN;
	}

	while (!stopsim) {
		if (z80_insn (&z, flags))
			stopsim = 1;
	}

	cleantty();
	return 0;
}
