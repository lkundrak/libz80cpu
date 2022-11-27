/*
 * Stupid Z80 processor emulator and disassembler.
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

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "z80.h"

uint8_t mem[0x10000];
int end;

static uint8_t
rd (struct z80 *z, uint16_t addr)
{
	uint8_t value;

	if (addr < end) {
		value = mem[addr];
	} else {
		fprintf (stderr, "Short read\n");
		value = 0xff;
	}
	return value;
}

int
main (int argc, char *argv[])
{
	struct z80 z = { 0, };
	enum z80_flags flags;
	int br;
	int fd;

	z.read = rd;
	end = z.r16[PC];

	switch (argc) {
	case 1:
		fd = STDIN_FILENO;
		break;
	case 2:
		fd = open (argv[1], O_RDONLY);
		if (fd == -1) {
			perror (argv[1]);
			return 1;
		}
		break;
	case 10:
		fprintf (stderr, "Are you stupid?\n");
	default:
		fprintf (stderr, "Usage: %s [<z.bin>]\n", argv[0]);
		return 1;
	}

	do {
		br = read (fd, &mem[end], sizeof(mem) - end);
		if (br == -1) {
			perror (argv[1]);
			return 1;
		}
		end += br;
	} while (br);

	flags = Z80_PRINT_ADDR;
	flags |= Z80_PRINT_DATA;
	flags |= Z80_PRINT_INSN;
	while (z.r16[PC] < end) {
		if (z80_insn (&z, flags))
			return 1;
	}

	return 0;
}
