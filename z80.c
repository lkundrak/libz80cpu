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

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "z80.h"

#ifdef Z80_NO_PRINT
#define PRINT_DATA 0
#define PRINT_ADDR 0
#define PRINT_INSN 0
#else
#define PRINT_DATA (flags & Z80_PRINT_DATA)
#define PRINT_ADDR (flags & Z80_PRINT_ADDR)
#define PRINT_INSN (flags & Z80_PRINT_INSN)
#endif

#ifdef Z80_NO_EXEC
#define EXEC 0
#else
#define EXEC (flags & Z80_EXEC)
#endif

#define P1(n)		!(n & 1)
#define P2(n)		(P1(n) == P1(n >> 1))
#define P4(n)		(P2(n) == P2(n >> 2))
#define P8(n)		(P4(n) == P4(n >> 4))

#define BIT(v,b)	!!((v) & (1 << (b)))

/* Memory access */
#define WR8(a,v)	z->write(z, (a), (v))
#define RD8(a)		z->read(z, (a))
#define WR16(a,v)	WR8((a), (v)); WR8((a)+1, (v) >> 8);
#define RD16(a)		(RD8((a)) | (RD8((a)+1) << 8))

/* Register access */
#define R8		z->r8
#define R16		z->r16

/* Flags */
enum flag { CF, NF, PF, XF, HF, YF, ZF, SF, VF=PF };
#define SF(f,n)		R8[F] = (R8[F] & ~(1 << (f))) | (!!(n) << (f))
#define GF(n)		BIT(R8[F], n)

static inline uint16_t
cf(struct z80 *z, const uint16_t a)
{
	SF(CF, !!(a & 0x100));
	return a;
}

static uint16_t
yx_flags(struct z80 *z, const uint16_t a)
{
	R8[F] &= ~(1 << XF | 1 << YF);
	R8[F] |= a & (1 << XF | 1 << YF);
	return a;
}
#define YX(a) yx_flags(z, a)

static uint16_t
yxc_flags(struct z80 *z, const uint16_t a)
{
	R8[F] &= ~(1 << HF | 1 << NF | 1 << XF | 1 << YF | 1 << CF);
	R8[F] |= (!!(a & 0x10)) << HF
		| (a & (1 << XF | 1 << YF));
	return cf(z, a);
}
#define YX_C(a) yxc_flags(z, a)

static uint16_t
p_flags(struct z80 *z, const uint16_t a, const uint8_t h)
{
	R8[F] &= ~(1 << SF  | 1 << ZF | 1 << HF | 1 << VF | 1 << NF);
	R8[F] |= (!!(a & 0x800) << SF)
		| (!(a & 0x0ff) << ZF)
		| (h << HF)
		| P8(a);

	return yx_flags(z, a);
}
#define F(a,h) p_flags(z, a, h)
#define F_C(a,h) cf(z, p_flags(z, a, h))

static uint16_t
add_sub(struct z80 *z, const uint16_t b, const uint16_t a, const bool sub)
{
	uint16_t res;

	res = sub ? b - a : b + a;

	R8[F] &= ~(1 << SF  | 1 << ZF | 1 << HF | 1 << VF | 1 << NF);
	R8[F] |= (!!(res & 0x800) << SF)
		| (!(res & 0x0ff) << ZF)
		| (res & (1 << HF))
		| ((b & 0x800) != (res & 0x800)) << VF
		| (sub << NF);

	return res;
}
#define ADD_SUB(b,a,n)   add_sub(z,b,a,n)
#define ADD_SUB_C(b,a,n) cf(z, add_sub(z,b,a,n))

static const enum z80_reg8 RI[] = { B, C, D, E, H, L, NUM_R8, A };
static const char *RN[] = { "b", "c", "d", "e", "h", "l", "(hl)", "a" };
#define GR(r)	(RI[r] == NUM_R8 ? RD8(R16[HL])    : R8[RI[r]])
#define SR(r,v)	(RI[r] == NUM_R8 ? WR8(R16[HL], v) : (R8[RI[r]] = v))
#define BR(r,b)	BIT(GR(r), b)

static const char *CN[] = { "nz", "z", "nc", "c", "po", "pe", "p", "m" };
static const enum flag CC[] = { ZF, CF, PF, SF };
#define c42	((op >> 4) & 0x03)
#define c31	((op >> 3) & 0x01)
#define c33	((op >> 3) & 0x07)
#define COND	GF(CC[c42]) == c31

static const enum z80_reg16 QI[] = { BC, DE, HL, SP };
static const char *QN[] = { "bc", "de", "hl", "sp" };
#define q24	((op >> 4) & 0x03)
#define Q24	R16[QI[q24]]

static const enum z80_reg16 PI[] = { BC, DE, HL, AF };
static const char *PN[] = { "bc", "de", "hl", "af" };
#define p24	((op >> 4) & 0x03)
#define P24	R16[PI[p24]]

static const enum z80_reg16 II[] = { IX, IY };
static const char *IN[] = { "ix", "iy" };
#define i5	((op0 >> 5) & 0x01)
#define I5	R16[II[i5]]

static const enum z80_reg8 JI[] = { IXH, IXL, IYH, IYL };
static const char *JN[] = { "ixh", "ixl", "iyh", "iyl" };
#define i5b0	((i5 << 1) | (op & 0x01))
#define I5B0	R8[JI[i5b0]]

#define v33	((op >> 3) & 0x07)
#define v30	(op & 0x07)
#define b33	((op >> 3) & 0x07)
#define IPD	I5 + d8
#define B3	(1 << b33)
#define REP	(op & 0x10)
#define S	(8*v33)

#define PRTO	(EXEC ? stderr : stdout)

#define XCHG(a,b) { typeof(a) t = a; a = b; b = t; }

#define FETCH(v) \
	v = RD8(R16[PC]++); \
	if (PRINT_DATA) column += fprintf(PRTO, "%02x ", (uint8_t)v);
#define FETCH16(v) \
	v = (R16[PC] += 2, RD16(R16[PC]-2)); \
	if (PRINT_DATA) column += fprintf(PRTO, "%04x ", (uint16_t)v);
#define FETCH_OP \
	R8[R]++; \
	FETCH(op);

static void
print_insn (enum z80_flags flags, int column, const char *fmt, ...)
{
	va_list ap;

	if (PRINT_DATA) {
		for (; column < 12; column++)
			putc (' ', PRTO);
	}

	va_start(ap, fmt);
	vfprintf(PRTO, fmt, ap);
	va_end(ap);

	putc('\n', PRTO);
}

#ifndef Z80_NO_PRINT
void
z80_dump (struct z80 *z)
{
	fprintf(stderr, "af=%04x af'=%04x ix=%04x sp=%04x\n",
		R16[AF], R16[AF_], R16[IX], R16[SP]);
	fprintf(stderr, "bc=%04x bc'=%04x iy=%04x pc=%04x\n",
		R16[BC], R16[BC_], R16[IY], R16[PC]);
	fprintf(stderr, "de=%04x de'=%04x iff1=%d  ir=%04x\n",
		R16[DE], R16[DE_], z->iff1, R16[IR]);
	fprintf(stderr, "hl=%04x hl'=%04x iff2=%d  im=%d  ",
		R16[HL], R16[HL_], z->iff2, z->im);
	putc(GF(SF) ? 'S' : 's', stderr);
	putc(GF(ZF) ? 'Z' : 'z', stderr);
	putc(GF(YF) ? 'Y' : 'y', stderr);
	putc(GF(HF) ? 'H' : 'h', stderr);
	putc(GF(XF) ? 'X' : 'x', stderr);
	putc(GF(PF) ? 'P' : 'p', stderr);
	putc(GF(NF) ? 'N' : 'n', stderr);
	putc(GF(CF) ? 'C' : 'c', stderr);
	putc('\n', stderr);
}
#endif

#define DIS(fmt,...) \
	if (PRINT_INSN) print_insn(flags, column, fmt, ## __VA_ARGS__); \
	if (EXEC == 0) return 0;

/*
 * The basic arithmetic-logic operations on A register follow the same
 * pattern regardless of the other operand.
 */

static int
do_al (struct z80 *z, enum z80_flags flags, int column, uint8_t op, uint8_t b)
{
	/* add a,X */
	switch (op & 0x38) {
	case 0x00:
		R8[A] = ADD_SUB_C(R8[A], b, 0);
		break;

	/* adc a,X */
	case 0x08:
		R8[A] = ADD_SUB_C(R8[A], b + GF(CF), 0);
		break;

	/* sub a,X */
	case 0x10:
		R8[A] = ADD_SUB_C(R8[A],  b, 1);
		break;

	/* sbc a,X */
	case 0x18:
		R8[A] = ADD_SUB_C(R8[A], b + GF(CF), 1);
		break;

	/* and X */
	case 0x20:
		R8[A] = F_C(R8[A] & b, 1);
		SF(CF, 0);
		break;

	/* xor X */
	case 0x28:
		R8[A] = F_C(R8[A] ^ b, 0);
		SF(CF, 0);
		break;

	/* or X */
	case 0x30:
		R8[A] = F_C(R8[A] | b, 0);
		SF(CF, 0);
		break;

	/* cp X */
	case 0x38:
		ADD_SUB_C(R8[A], b, 1);
		YX(b);
		break;
	}

	return 0;
}
static const char *aln[] = { "add", "adc", "sub", "sbc", "and", "xor", "or", "cp" };
#define ALN aln[(op >> 3) & 7]

static int
do_ed (struct z80 *z, enum z80_flags flags, int column)
{
	uint16_t v16;
	uint8_t op;

	FETCH_OP

	switch (op & 0xff) {
	/* ld i,a */
	case 0x47:
		DIS("ld i, a")
		R8[I] = R8[A];
		return 0;

	/* ld r,a */
	case 0x4f:
		DIS("ld r, a")
		R8[R] = R8[A];
		return 0;

	/* ld a,i */
	case 0x57:
		DIS("ld a, i")
		R8[A] = F_C(R8[I], 0);
		SF(PF, z->iff2);
		return 0;

	/* ld a,r */
	case 0x5f:
		DIS("ld a, r")
		R8[A] = F_C(R8[R], 0);
		SF(PF, z->iff2);
		return 0;

	/* rrd */
	case 0x67:
		DIS("rrd")
		v16 = RD8(R16[HL]);
		WR8(R16[HL], (v16 >> 4) + ((R8[A] & 0x0f) << 4));
		R8[A] = F((R8[A] & 0xf0) + (v16 & 0x0f), 0);
		return 3;

	/* rld */
	case 0x6f:
		DIS("rld")
		v16 = (RD8(R16[HL]) << 4) + (R8[A] & 0x0f);
		WR8(R16[HL], v16);
		R8[A] = F((R8[A] & 0xf0) + (v16 >> 8), 0);
		return 3;

	/* in f,(c) */
	case 0x70:
		DIS("in f, (c)")
		F(z->in(z, R8[C]), 0);
		return 0;

	/* out (c),0 */
	case 0x71:
		DIS("out (c), 0")
		z->out(z, R8[C], 0); /* Told to vary with CPU */
		return 0;
	}

	switch (op & 0xef) {
	/* cpd/cpdr */
	case 0xa9:
		DIS(REP ? "cpdr" : "cpd")
		YX((F(R8[A] - RD8(R16[HL]--), 1) - GF(HF)) >> 2);
		R16[BC]--;
		if (REP && R16[BC] & !GF(ZF)) R16[PC] -= 2;
		return 0;

	/* cpi/cpir */
	case 0xa1:
		YX((F(R8[A] - RD8(R16[HL]++), 1) - GF(HF)) >> 2);
		R16[BC]--;
		if (REP && R16[BC] & !GF(ZF)) R16[PC] -= 2;
		return 0;

	/* ind/indr */
	case 0xaa:
		DIS(REP ? "indr" : "ind")
		WR8(R16[HL], z->in(z, R8[C]));
		F_C(R8[B]--, 0);
		SF(HF, (RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) > 0xff);
		SF(PF, P8((RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) & 0x07) ^ R8[B]);
		SF(NF, BIT(RD8(R16[HL]), 7));
		SF(CF, GF(HF));
		R16[HL]--;
		if (REP && R8[B]) R16[PC] -= 2;
		return 0;

	/* ini/inir */
	case 0xa2:
		DIS(REP ? "indr" : "ind")
		WR8(R16[HL], z->in(z, R8[C]));
		F_C(R8[B]--, 0);
		SF(HF, (RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) > 0xff);
		SF(PF, P8((RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) & 0x07) ^ R8[B]);
		SF(NF, BIT(RD8(R16[HL]), 7));
		SF(CF, GF(HF));
		R16[HL]++;
		if (REP && R8[B]) R16[PC] -= 2;
		return 0;

	/* ldd/lddr */
	case 0xa8:
		DIS(REP ? "lddr" : "ldd")
		YX((RD8(R16[HL]) + R8[A]) >> 2);
		WR8(R16[DE], RD8(R16[HL]));
		R16[DE]--;
		R16[HL]--;
		R16[BC]--;
		if (REP && R16[BC]) R16[PC] -= 2;
		return 0;

	/* ldi/ldir */
	case 0xa0:
		DIS(REP ? "ldir" : "ldi")
		YX((RD8(R16[HL]) + R8[A]) >> 2);
		WR8(R16[DE], RD8(R16[HL]));
		R16[DE]++;
		R16[HL]++;
		R16[BC]--;
		if (REP && R16[BC]) R16[PC] -= 2;
		return 0;

	/* outd/otdr */
	case 0xab:
		DIS(REP ? "otdr" : "outd")
		z->out(z, R8[C], RD8(R16[HL]));
		F_C(R8[B]--, 0);
		SF(HF, (RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) > 0xff);
		SF(PF, P8((RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) & 0x07) ^ R8[B]);
		SF(NF, BIT(RD8(R16[HL]), 7));
		SF(CF, GF(HF));
		R16[HL]--;
		if (REP && R8[B]) R16[PC] -= 2;
		return 0;

	/* outi/otir */
	case 0xa3:
		DIS(REP ? "otir" : "outi")
		z->out(z, R8[C], RD8(R16[HL]));
		F_C(R8[B]--, 0);
		SF(HF, (RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) > 0xff);
		SF(PF, P8((RD8(R16[HL]) + ((R8[C] - 1) & 0xff)) & 0x07) ^ R8[B]);
		SF(NF, BIT(RD8(R16[HL]), 7));
		SF(CF, GF(HF));
		R16[HL]++;
		if (REP && R8[B]) R16[PC] -= 2;
		return 0;
	}

	switch (op & 0xcf) {
	/* retn */
	case 0x45:
		DIS("retn")
		R16[PC] = RD16(R16[SP]);
		R16[SP] += 2;
		z->iff1 = z->iff2;
		return 0;

	/* reti */
	case 0x4d:
		DIS("reti")
		R16[PC] = RD16(R16[SP]);
		R16[SP] += 2;
		z->iff1 = z->iff2;
		return 0;

	/* sbc hl,Q */
	case 0x42:
		DIS("sbc hl, %s", QN[q24])
		R16[HL] = ADD_SUB_C(R16[HL], Q24 + GF(CF), 1);
		return 0;

	/* adc hl,Q */
	case 0x4a:
		DIS("adc hl, %s", QN[q24])
		R16[HL] = ADD_SUB_C(R16[HL], Q24 + GF(CF), 0);
		return 0;

	/* ld (A),Q */
	case 0x43:
		/* ld (A),hl has a better encoding. */
		FETCH16(v16)
		DIS("ld (0x%04x), %s", v16, QN[q24])
		WR16(v16, Q24)
		return 0;

	/* ld Q,(A) */
	case 0x4b:
		/* ld hl,(A) has a better encoding. */
		FETCH16(v16)
		DIS("ld %s, (0x%04x)", QN[q24], v16)
		Q24 = RD16(v16);
		return 0;
	}

	switch (op & 0xc7) {
	/* neg */
	case 0x44:
		DIS("neg")
		R8[A] = ADD_SUB_C(0, R8[A], 1);
		SF(PF, (uint8_t)R8[A] == 0x80);
		return 10;

	/* in R,(c) */
	case 0x40:
		DIS("in %s, (c)", RN[v33])
		SR(v33, F(z->in(z, R8[C]), 0));
		return 0;

	/* out (c),R */
	case 0x41:
		DIS("out (c), %s", RN[v33])
		z->out(z, R8[C], GR(v33));
		return 0;
	}

	/* im 0 */
	if ((op & 0xd7) == 0x46) {
		DIS("im 0")
		z->im = 0;
		return 0;
	}

	switch (op & 0xdf) {
	/* im 1 */
	case 0x56:
		DIS("im 1")
		z->im = 1;
		return 0;

	/* im 2 */
	case 0x5e:
		DIS("im 2")
		z->im = 2;
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

static int
do_cb (struct z80 *z, enum z80_flags flags, int column)
{
	uint8_t op;

	FETCH_OP

	switch (op & 0xc0) {
	/* bit B,R */
	case 0x40:
		DIS("bit %d, %s", b33, RN[v30])
		F(GR(v30) & B3, 1);
		return 0;

	/* res B,R */
	case 0x80:
		DIS("res %d, %s", b33, RN[v30])
		SR(v30, GR(v30) & ~(B3));
		return 0;

	/* set B,R */
	case 0xc0:
		DIS("set %d, %s", b33, RN[v30])
		SR(v30, GR(v30) | B3);
		return 0;
	}

	switch (op & 0xf8) {
	/* rlc R */
	case 0x00:
		DIS("rlc %s", RN[v30])
		SF(CF, BR(v30, 7));
		SR(v30, F((GR(v30) << 1) + GF(CF), 0));
		return 0;

	/* rrc R */
	case 0x08:
		DIS("rrc %s", RN[v30])
		SF(CF, BR(v30, 0));
		SR(v30, F((GR(v30) >> 1) + (GF(CF) << 7), 0));
		return 0;

	/* rl R */
	case 0x10:
		DIS("rl %s", RN[v30])
		SR(v30, F_C((GR(v30) << 1) + GF(CF), 0));
		return 0;

	/* rr R */
	case 0x18:
		DIS("rr %s", RN[v30])
		SR(v30, F_C((GR(v30) + (GF(CF) << 8) + (BR(v30, 0) << 9)) >> 1, 0));
		return 0;

	/* sla R */
	case 0x20:
		DIS("sla %s", RN[v30])
		SF(CF, BR(v30, 7));
		SR(v30, F(GR(v30) << 1, 0));
		return 0;

	/* sra R */
	case 0x28:
		DIS("sra %s", RN[v30])
		SF(CF, BR(v30, 0));
		SR(v30, F((int8_t)GR(v30) >> 1, 0));
		return 0;

	/* sll R */
	case 0x30:
		DIS("sll %s", RN[v30])
		SF(CF, BR(v30, 7));
		SR(v30, F((GR(v30) << 1) + 1, 0));
		return 0;

	/* srl R */
	case 0x38:
		DIS("srl %s", RN[v30])
		SF(CF, BR(v30, 0));
		SR(v30, F(GR(v30) >> 1, 0));
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

static int
do_dd (struct z80 *z, enum z80_flags flags, int column)
{
	uint8_t op;

	FETCH_OP

	switch (op & 0xff) {
	/* ld ixh,ixl */
	case 0x65:
		DIS("ld ixh, ixl")
		R8[IXH] = R8[IXL];
		return 0;

	/* ld ixl,ixh */
	case 0x6c:
		DIS("ld ixl, ixh")
		R8[IXL] = R8[IXH];
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

static int
do_fd (struct z80 *z, enum z80_flags flags, int column)
{
	uint8_t op;

	FETCH_OP

	switch (op & 0xff) {
	/* ld iyh,iyl */
	case 0x65:
		DIS("ld iyh, iyl")
		R8[IYH] = R8[IYL];
		return 0;

	/* ld iyl,iyh */
	case 0x6c:
		DIS("ld iyl, iyh")
		R8[IYL] = R8[IYH];
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

static int
do_idd_cb (struct z80 *z, enum z80_flags flags, int column, uint8_t op0)
{
	uint8_t op;
	int8_t d8;

	FETCH(d8)
	FETCH_OP

	switch (op & 0xc7) {
	/* res B,(I+D) */
	case 0x86:
		DIS("res %d, (%s+%d)", b33, IN[i5], d8)
		WR8(IPD, RD8(IPD) & ~(B3));
		return 0;

	/* set B,(I+D) */
	case 0xc6:
		DIS("set %d, (%s+%d)", b33, IN[i5], d8)
		WR8(IPD, RD8(IPD) | B3);
		return 0;
	}

	switch (op & 0xc0) {
	/* bit B,(I+D) */
	case 0x40:
		DIS("bit %d, (%s+%d)", b33, IN[i5], d8)
		F(RD8(IPD) & B3, 1);
		YX(RD8(IPD + 1));
		return 0;

	/* res B,(I+D)->R */
	case 0x80:
		DIS("res %d, (%s+%d->%s)", b33, IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, RD8(IPD) & ~(B3)));
		return 0;

	/* set B,(I+D)->R */
	case 0xc0:
		DIS("set %d, (%s+%d->%s)", b33, IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, RD8(IPD) | B3));
		return 0;
	}

	switch (op & 0xff) {
	/* rl (I+D) */
	case 0x16:
		DIS("rl (%s+%d)", IN[i5], d8)
		WR8(IPD, F_C((RD8(IPD) << 1) + GF(CF), 0));
		return 0;

	/* rlc (I+D) */
	case 0x06:
		DIS("rlc (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, F((RD8(IPD) << 1) + GF(CF), 0));
		return 0;

	/* rr (I+D) */
	case 0x1e:
		DIS("rr (%s+%d)", IN[i5], d8)
		WR8(IPD, F_C((RD8(IPD) + (GF(CF) << 8) + (BIT(RD8(IPD), 0) << 9)) >> 1, 0));
		return 0;

	/* rrc (I+D) */
	case 0x0e:
		DIS("rrc (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, F((RD8(IPD) >> 1) + (GF(CF) << 7), 0));
		return 0;

	/* sla (I+D) */
	case 0x26:
		DIS("sla (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, F(RD8(IPD) << 1, 0));
		return 0;

	/* sra (I+D) */
	case 0x2e:
		DIS("sra (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, F((int8_t)RD8(IPD) >> 1, 0));
		return 0;

	/* sll (I+D) */
	case 0x36:
		DIS("sll (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, F((RD8(IPD) << 1) + 1, 0));
		return 0;

	/* srl (I+D) */
	case 0x3e:
		DIS("srl (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, F(RD8(IPD) >> 1, 0));
		return 0;
	}

	switch (op & 0xf8) {
	/* rl (I+D)->R */
	case 0x10:
		DIS("rl (%s+%d->%s)", IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, F_C((RD8(IPD) << 1) + GF(CF), 0)));
		return 0;

	/* rlc (I+D)->R */
	case 0x00:
		DIS("rlc (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, SR(v30, F((RD8(IPD) << 1) + GF(CF), 0)));
		return 0;

	/* rr (I+D)->R */
	case 0x18:
		DIS("rr (%s+%d->%s)", IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, F_C((RD8(IPD) + (GF(CF) << 8) + (BIT(RD8(IPD), 0) << 9)) >> 1, 0)));
		return 0;

	/* rrc (I+D)->R */
	case 0x08:
		DIS("rrc (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, SR(v30, F((RD8(IPD) >> 1) + (GF(CF) << 7), 0)));
		return 0;

	/* sla (I+D)->R */
	case 0x20:
		DIS("sla (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, SR(v30, F(RD8(IPD) << 1, 0)));
		return 0;

	/* sra (I+D)->R */
	case 0x28:
		DIS("sra (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, SR(v30, F((int8_t)RD8(IPD) >> 1, 0)));
		return 0;

	/* sll (I+D)->R */
	case 0x30:
		DIS("sll (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, SR(v30, F((RD8(IPD) << 1) + 1, 0)));
		return 0;

	/* srl (I+D)->R */
	case 0x38:
		DIS("srl (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, SR(v30, F(RD8(IPD) >> 1, 0)));
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

static int
do_idd (struct z80 *z, enum z80_flags flags, int column, uint8_t op0)
{
	uint8_t op, n8;
	uint16_t v16;
	int8_t d8;

	FETCH_OP

	switch (op & 0xff) {
	/* ld I,A */
	case 0x21:
		FETCH16(v16)
		DIS("ld %s, 0x%04x", IN[i5], v16)
		I5 = v16;
		return 0;

	/* ld (A),I */
	case 0x22:
		FETCH16(v16)
		DIS("ld (0x%04x), %s", v16, IN[i5])
		WR8(v16, I5);
		return 0;

	/* inc I */
	case 0x23:
		DIS("inc %s", IN[i5])
		I5 += 1;
		return 0;

	/* ld I,(A) */
	case 0x2a:
		FETCH16(v16)
		DIS("ld %s, (0x%04x)", IN[i5], v16)
		I5 = RD8(v16);
		return 0;

	/* dec I */
	case 0x2b:
		DIS("dec %s", IN[i5])
		I5 -= 1;
		return 0;

	/* inc (I+D) */
	case 0x34:
		FETCH(d8)
		DIS("inc (%s+%d)", IN[i5], d8)
		WR8(IPD, ADD_SUB(RD8(IPD), 1, 0));
		return 0;

	/* dec (I+D) */
	case 0x35:
		FETCH(d8)
		DIS("dec (%s+%d)", IN[i5], d8)
		WR8(IPD, ADD_SUB(RD8(IPD), 1, 1));
		return 0;

	/* ld (I+D),N */
	case 0x36:
		FETCH(d8)
		FETCH(n8)
		DIS("ld (%s+%d), 0x%02x", IN[i5], d8, n8)
		WR8(IPD, n8);
		return 0;

	/* pop I */
	case 0xe1:
		DIS("pop %s", IN[i5])
		I5 = RD16(R16[SP]);
		R16[SP] += 2;
		return 0;

	/* ex (sp),I */
	case 0xe3:
		DIS("ex (sp), %s", IN[i5])
		v16 = RD16(R16[SP]);
		WR16(R16[SP], I5)
		I5 = v16;
		return 0;

	/* push I */
	case 0xe5:
		DIS("push %s", IN[i5])
		R16[SP] -= 2;
		WR16(R16[SP], I5)
		return 0;

	/* jp (I) */
	case 0xe9:
		DIS("jp (%s)", IN[i5])
		R16[PC] = I5;
		return 0;

	/* ld sp,I */
	case 0xf9:
		DIS("ld sp, %s", IN[i5])
		R16[SP] = I5;
		return 0;
	case 0xcb:
		/* Extended */
		return do_idd_cb (z, flags, column, op);
	}

	switch (op & 0xf7) {
	/* inc J */
	case 0x24:
		DIS("inc %s", JN[i5b0])
		I5B0 = ADD_SUB(I5B0, 1, 0);
		return 0;

	/* dec J */
	case 0x25:
		DIS("dec %s", JN[i5b0])
		I5B0 = ADD_SUB(I5B0, 1, 1);
		return 0;
	}

	/* add I,Q */
	if ((op & 0xcf) == 0x09) {
		DIS("add %s, %s", IN[i5], QN[q24])
		I5 = YX_C(I5 + Q24);
		return 0;
	}

	/* ld J,R */
	if ((op & 0xf0) == 0x60) {
		DIS("ld %s, %s", JN[i5b0], RN[v30])
		I5B0 = GR(v30);
		return 0;
	}

	switch (op & 0xc6) {
	/* ld R,J */
	case 0x44:
		DIS("ld %s, %s", RN[v33], JN[i5b0])
		SR(v33, I5B0);
		return 0;

	/* <al> a,J */
	case 0x84:
		DIS("%s a, %s", ALN, JN[i5b0])
		return do_al (z, flags, column, op, I5B0);
	}

	switch (op & 0xc7) {
	/* ld R,(I+D) */
	case 0x46:
		FETCH(d8)
		DIS("ld %s, (%s+%d)", RN[v33], IN[i5], d8)
		SR(v33, RD8(IPD));
		return 0;

	/* <al> a,(I+D) */
	case 0x86:
		FETCH(d8)
		DIS("%s a, (%s+%d)", IN[i5], ALN, d8)
		return do_al (z, flags, column, op, RD8(IPD));
	}

	/* ld (I+D),R */
	if ((op & 0xf8) == 0x70) {
		FETCH(d8)
		DIS("ld (%s+%d), %s", IN[i5], d8, RN[v30])
		WR8(IPD, GR(v30));
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

int
z80_insn (struct z80 *z, enum z80_flags flags)
{
	int column = 0;
	uint8_t n8, op;
	uint16_t v16;
	int8_t d8;

	if (PRINT_ADDR)
		fprintf (PRTO, "%04x: ", R16[PC]);

	FETCH_OP

	switch (op & 0xff) {
	/* nop */
	case 0x00:
		DIS("nop")
		/* nothing */;
		return 0;

	/* ld (bc),a */
	case 0x02:
		DIS("ld (bc), a")
		WR8(R16[BC], R8[A]);
		return 0;

	/* ld a,(bc) */
	case 0x0a:
		DIS("ld a, (bc)")
		R8[A] = RD8(R16[BC]);
		return 0;

	/* ld (de),a */
	case 0x12:
		DIS("ld (de), a")
		WR8(R16[DE], R8[A]);
		return 0;

	/* ld a,(de) */
	case 0x1a:
		DIS("ld a, (de)")
		R8[A] = RD8(R16[DE]);
		return 0;

	/* halt */
	case 0x76:
		DIS("halt")
		/* wait for interrupt */;
		return 2;

	/* ret */
	case 0xc9:
		DIS("ret")
		R16[PC] = RD16(R16[SP]);
		R16[SP] += 2;
		return 0;

	/* exx */
	case 0xd9:
		DIS("exx")
		XCHG(R16[BC], R16[BC_]);
		XCHG(R16[DE], R16[DE_]);
		XCHG(R16[HL], R16[HL_]);
		return 0;

	/* ex (sp),hl */
	case 0xe3:
		DIS("ex (sp), hl")
		v16 = RD16(R16[SP]);
		WR16(R16[SP], R16[HL])
		R16[HL] = v16;
		return 0;

	/* jp (hl) */
	case 0xe9:
		DIS("jp (hl)")
		R16[PC] = R16[HL];
		return 0;

	/* ex de,hl */
	case 0xeb:
		DIS("ex de, hl")
		XCHG(R16[DE], R16[HL]);
		return 0;

	/* di */
	case 0xf3:
		DIS("di")
		z->iff1 = 0;
		z->iff2 = 0;
		return 0;

	/* ld sp,hl */
	case 0xf9:
		DIS("ld sp, hl")
		R16[SP] = R16[HL];
		return 0;

	/* ei */
	case 0xfb:
		DIS("ei")
		z->iff2 = 1; /* FIXME: after the next instruction */
		return 0;

	/* djnz E */
	case 0x10:
		FETCH(d8)
		DIS("djnz %d", d8)
		if (R8[B] -= 1) R16[PC] += d8;
		return 0;

	/* jr E */
	case 0x18:
		FETCH(d8)
		DIS("jr %d", d8)
		R16[PC] += d8;
		return 0;

	/* jr nz,E */
	case 0x20:
		FETCH(d8)
		DIS("jr nz, %d", d8)
		if (!GF(ZF)) R16[PC] += d8;
		return 0;

	/* jr z,E */
	case 0x28:
		FETCH(d8)
		DIS("jr z, %d", d8)
		if (GF(ZF)) R16[PC] += d8;
		return 0;

	/* jr nc,E */
	case 0x30:
		FETCH(d8)
		DIS("jr nc, %d", d8)
		if (!GF(CF)) R16[PC] += d8;
		return 0;

	/* jr c,E */
	case 0x38:
		FETCH(d8)
		DIS("jr c, %d", d8)
		if (GF(CF)) R16[PC] += d8;
		return 0;

	/* out (N),a */
	case 0xd3:
		FETCH(n8)
		DIS("out (0x%02x), a", n8)
		z->out(z, n8, R8[A]);
		return 0;

	/* in a,(N) */
	case 0xdb:
		FETCH(n8)
		DIS("in a, (0x%02x)", n8)
		R8[A] = z->in(z, n8);
		return 0;

	/* ld (A),hl */
	case 0x22:
		FETCH16(v16)
		DIS("ld (0x%04x), hl", v16)
		WR8(v16, R8[L]);
		WR8(v16+1, R8[H]);
		return 0;

	/* ld hl,(A) */
	case 0x2a:
		FETCH16(v16)
		DIS("ld hl, (0x%04x)", v16)
		R8[L] = RD8(v16);
		R8[H] = RD8(v16+1);
		return 0;

	/* ld (A),a */
	case 0x32:
		FETCH16(v16)
		DIS("ld (0x%04x), a", v16)
		WR8(v16, R8[A]);
		return 0;

	/* ld a,(A) */
	case 0x3a:
		FETCH16(v16)
		DIS("ld a, (0x%04x)", v16)
		R8[A] = RD8(v16);
		return 0;

	/* jp A */
	case 0xc3:
		FETCH16(v16)
		DIS("jp 0x%04x", v16)
		R16[PC] = v16;
		return 0;

	/* call A */
	case 0xcd:
		FETCH16(v16)
		DIS("call 0x%04x", v16)
		R16[SP] -= 2;
		WR16(R16[SP], R16[PC])
		R16[PC] = v16;
		return 0;

	/* ex af,af' */
	case 0x08:
		DIS("ex af, af'")
		XCHG(R16[AF], R16[AF_]);
		return 0;

	/* rlca */
	case 0x07:
		DIS("rlca")
		R8[A] = YX_C((R8[A] << 1) + GF(CF));
		SF(HF, 0);
		return 0;

	/* rra */
	case 0x1f:
		DIS("rra")
		R8[A] = YX_C(((BIT(R8[A], 0) << 9) + (GF(CF) << 8) + (uint8_t)R8[A]) >> 1);
		SF(HF, 0);
		return 0;

	/* rrca */
	case 0x0f:
		DIS("rrca")
		R8[A] = YX_C(((BIT(R8[A], 0) << 9) + (BIT(R8[A], 0) << 8) + (uint8_t)R8[A]) >> 1);
		SF(HF, 0);
		return 0;

	/* rla */
	case 0x17:
		DIS("rla")
		R8[A] = YX_C((R8[A] << 1) + GF(CF));
		SF(HF, 0);
		return 0;

	/* daa */
	case 0x27:
		DIS("daa")
		v16 = R8[A];
		if (GF(HF) || (R8[A] & 0x0f) > 9)
			v16 += (GF(NF) ? -0x06 : 0x06);
		if (GF(CF) || R8[A] > 0x99)
			v16 += (GF(NF) ? -0x60 : 0x60);
		F(v16, BIT(R8[A], 4) ^ BIT(v16, 4));
		if (R8[A] > 0x99)
			SF(CF, 1);
		R8[A] = v16;
		return 0;

	/* cpl */
	case 0x2f:
		DIS("cpl")
		R8[A] = YX(~(R8[A]));
		SF(HF, 1);
		SF(NF, 1);
		return 0;

	/* scf */
	case 0x37:
		DIS("scf")
		YX(R8[A] | R8[F]);
		SF(HF, 0);
		SF(NF, 0);
		SF(CF, 1);
		return 0;

	/* ccf */
	case 0x3f:
		DIS("ccf")
		YX(R8[A] | R8[F]);
		SF(HF, GF(CF));
		SF(NF, 0);
		SF(CF, !GF(CF));
		return 0;
	}

	/* Extended instructions. */
	if ((op & 0xdf) == 0xdd) {
		return do_idd (z, flags, column, op);
	}
	switch (op & 0xff) {
	case 0xed:
		return do_ed (z, flags, column);
	case 0xcb:
		return do_cb (z, flags, column);
	case 0xdd:
		return do_dd (z, flags, column);
	case 0xfd:
		return do_fd (z, flags, column);
	}

	switch (op & 0xcf) {
	/* inc Q */
	case 0x03:
		DIS("inc %s", QN[q24])
		Q24 += 1;
		return 0;

	/* add hl,Q */
	case 0x09:
		DIS("add hl, %s", QN[q24])
		R16[HL] = YX_C(R16[HL] + Q24);
		return 0;

	/* dec Q */
	case 0x0b:
		DIS("dec %s", QN[q24])
		Q24 -= 1;
		return 0;
	}

	switch (op & 0xc7) {
	/* inc R */
	case 0x04:
		DIS("inc %s", RN[v33])
		SR(v33, ADD_SUB(GR(v33), 1, 0));
		return 0;

	/* dec R */
	case 0x05:
		DIS("dec %s", RN[v33])
		SR(v33, ADD_SUB(GR(v33), 1, 1));
		return 0;

	/* <al> a,N */
	case 0xc6:
		FETCH(n8)
		DIS("%s a, 0x%02x", ALN, n8)
		return do_al (z, flags, column, op, n8);
	}

	switch (op & 0xc0) {
	/* ld R1,R2 */
	case 0x40:
		DIS("ld %s, %s", RN[v33], RN[v30])
		SR(v33, GR(v30));
		return 0;

	/* <al> a,R */
	case 0x80:
		DIS("%s a, %s", ALN, RN[v30])
		return do_al (z, flags, column, op, GR(v30));
	}

	switch (op & 0xcf) {
	/* pop P */
	case 0xc1:
		DIS("pop %s", PN[p24])
		P24 = RD16(R16[SP]);
		R16[SP] += 2;
		return 0;

	/* push P */
	case 0xc5:
		DIS("push %s", PN[p24])
		R16[SP] -= 2;
		WR16(R16[SP], P24)
		return 0;
	}

	switch (op & 0xc7) {
	/* ld R,N */
	case 0x06:
		FETCH(n8)
		DIS("ld %s, 0x%02x", RN[v33], n8)
		SR(v33, n8);
		return 0;

	/* jp C,A */
	case 0xc2:
		FETCH16(v16)
		DIS("jp %s, 0x%04x", CN[v33], v16)
		if (COND) R16[PC] = v16;
		return 0;

	/* call C,A */
	case 0xc4:
		FETCH16(v16)
		DIS("call %s, 0x%04x", CN[v33], v16)
		if (COND) {
			R16[SP] -= 2;
			WR16(R16[SP], R16[PC])
			R16[PC] = v16;
		}
		return 0;

	/* ret C */
	case 0xc0:
		DIS("ret %s", CN[v33])
		if (COND) {
			R16[PC] = RD16(R16[SP]);
			R16[SP] += 2;
		}
		return 0;

	/* rst S */
	case 0xc7:
		DIS("rst %d", S)
		R16[SP] -= 2;
		WR16(R16[SP], R16[PC])
		R16[PC] = S;
		return 0;
	}

	/* ld Q,A */
	if ((op & 0xcf) == 0x01) {
		FETCH16(v16)
		DIS("ld %s, 0x%04x", QN[q24], v16)
		Q24 = v16;
		return 0;
	}

	DIS("(bad op)");
	return -1;
}

void
z80_nmi (struct z80 *z)
{
	z->iff2 = z->iff1;
	z->iff1 = 0;
	R16[SP] -= 2;
	WR16(R16[SP], R16[PC])
	R16[PC] = 0x0066;
}
