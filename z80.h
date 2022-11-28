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

#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum z80_flags {
#ifndef Z80_NO_PRINT
	Z80_PRINT_ADDR	= 0x01,
	Z80_PRINT_DATA	= 0x02,
	Z80_PRINT_REGS	= 0x04,
	Z80_PRINT_INSN	= 0x08,
#endif
#ifndef Z80_NO_EXEC
	Z80_EXEC	= 0x10,
#endif
};

enum z80_reg16 {
	AF, BC, DE, HL,
	AF_, BC_, DE_, HL_,
	IR,
	IX, IY,
	SP, PC,
	NUM_R16,
};

#if BYTE_ORDER == BIG_ENDIAN
#define _REG8(h, l, r) h=(r*2), l=(r*2+1),
#else
#define _REG8(h, l, r) h=(r*2+1), l=(r*2),
#endif
enum z80_reg8 {
	_REG8(A,   F,   AF)
	_REG8(B,   C,   BC)
	_REG8(D,   E,   DE)
	_REG8(H,   L,   HL)
	_REG8(A_,  F_,  AF_)
	_REG8(B_,  C_,  BC_)
	_REG8(D_,  E_,  DE_)
	_REG8(H_,  L_,  HL_)
	_REG8(I,   R,   IR)
	_REG8(IXH, IXL, IX)
	_REG8(IYH, IYL, IY)
	NUM_R8 = NUM_R16*2,
};
#undef _REG8

struct z80 {
	union {
		uint16_t r16[NUM_R16];
		int8_t r8[NUM_R8];
	} __attribute__((packed));
	bool iff1:1, iff2:1;
	int im;

	uint8_t (*read)(struct z80 *z, uint16_t addr);
	uint8_t (*write)(struct z80 *z, uint16_t addr, uint8_t val);
	uint8_t (*in)(struct z80 *z, uint8_t addr);
	void (*out)(struct z80 *z, uint8_t addr, uint8_t val);
};

int z80_insn (struct z80 *z, enum z80_flags flags);
void z80_nmi (struct z80 *z);

#ifndef Z80_NO_PRINT
void z80_dump (struct z80 *z);
#endif
