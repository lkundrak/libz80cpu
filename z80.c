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
#define PRINT_REGS 0
#define PRINT_INSN 0
#else
#define PRINT_DATA (flags & Z80_PRINT_DATA)
#define PRINT_ADDR (flags & Z80_PRINT_ADDR)
#define PRINT_REGS (flags & Z80_PRINT_REGS)
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
	R8[F] |= (a & (1 << XF | 1 << YF));
	return cf(z, a);
}
#define YX_C(a) yxc_flags(z, a)

static uint16_t
szyhx_flags(struct z80 *z, const uint16_t a, const uint8_t h)
{
	R8[F] &= ~(1 << SF  | 1 << ZF | 1 << HF);
	R8[F] |= (!!(a & 0x080) << SF)
		| (!(a & 0x0ff) << ZF)
		| (h << HF);

	return yx_flags (z, a);
}
#define SZYHX(a, h) szyhx_flags(z, a, h)

static uint16_t
p_flags(struct z80 *z, const uint16_t a, const uint8_t h)
{
	R8[F] &= ~(1 << PF | 1 << NF);
	R8[F] |= (P8(a) << PF);

	return szyhx_flags(z, a, h);
}
#define F(a,h) p_flags(z, a, h)
#define F_C(a,h) cf(z, p_flags(z, a, h))

static uint16_t
add_sub(struct z80 *z, const uint16_t a, const uint16_t b, const uint8_t c, const bool sub)
{
	uint16_t res;
	uint8_t h, v;

	if (sub) {
		res = a - b - c;
		h = ((a & 0xf) < (res & 0xf)) || (c && (res & 0xf) == 0xf);
		v = ((a & 0x80) != (b & 0x80)) && ((a & 0x80) != (res & 0x80));
	} else {
		res = a + b + c;
		h = ((a & 0xf) > ((res-c) & 0xf)) || (c && (res & 0xf) == 0x0);
		v = ((a & 0x80) == (b & 0x80)) && ((a & 0x80) != (res & 0x80));
	}

	R8[F] &= ~(1 << VF | 1 << NF);
	R8[F] |= (v << VF) | (sub << NF);

	return szyhx_flags (z, res, h);
}
#define ADD_SUB(a,b,sub)	add_sub(z,a,b,0,sub)
#define ADD_SUB_C(a,b,sub)	cf(z, add_sub(z,a,b,0,sub))
#define ADD_SUB_CC(a,b,sub)	cf(z, add_sub(z,a,b,GF(CF),sub))

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
#define XN24	(q24 == 2 ? IN[i5] : QN[q24])
#define X24	(q24 == 2 ? I5 : Q24 )

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
#define i5b3	((i5 << 1) | ((op >> 3) & 1))
#define I5B3	R8[JI[i5b3]]

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
static void
print_regs (struct z80 *z, FILE *prto, const char sep)
{
	fprintf(prto, "pc=%04x sp=%04x%c", R16[PC], R16[SP], sep);
	fprintf(prto, "af=%04x bc=%04x de=%04x hl=%04x%c",
		R16[AF], R16[BC], R16[DE], R16[HL], sep);
	fprintf(prto, "af'=%04x bc'=%04x de'=%04x hl'=%04x%c",
		R16[AF_], R16[BC_], R16[DE_], R16[HL_], sep);
	fprintf(prto, "ix=%04x iy=%04x ir=%04x%c",
		R16[IX], R16[IY], R16[IR], sep);
	fprintf(prto, "im=%d iff1=%d iff2=%d%c",
		z->im, z->iff1, z->iff2, sep);

	putc('[', prto);
	putc(GF(SF) ? 'S' : 's', prto);
	putc(GF(ZF) ? 'Z' : 'z', prto);
	putc(GF(YF) ? 'Y' : 'y', prto);
	putc(GF(HF) ? 'H' : 'h', prto);
	putc(GF(XF) ? 'X' : 'x', prto);
	putc(GF(PF) ? 'P' : 'p', prto);
	putc(GF(NF) ? 'N' : 'n', prto);
	putc(GF(CF) ? 'C' : 'c', prto);
	putc(']', prto);
	putc(' ', prto);
}

void
z80_dump (struct z80 *z)
{
	print_regs (z, stderr, '\n');
}
#endif

#define DIS(fmt,...) \
	if (PRINT_INSN) print_insn(flags, column, fmt, ## __VA_ARGS__); \
	if (EXEC == 0) return Z80_OP_GOOD;

/*
 * The basic arithmetic-logic operations on A register follow the same
 * pattern regardless of the other operand.
 */

static enum z80_result
do_al (struct z80 *z, enum z80_flags flags, int column, int8_t op, uint8_t b)
{
	uint8_t a = R8[A];

	/* add a,X */
	switch (op & 0x38) {
	case 0x00:
		R8[A] = ADD_SUB_C(a, b, 0);
		break;

	/* adc a,X */
	case 0x08:
		R8[A] = ADD_SUB_CC(a, b, 0);
		break;

	/* sub a,X */
	case 0x10:
		R8[A] = ADD_SUB_C(a, b, 1);
		break;

	/* sbc a,X */
	case 0x18:
		R8[A] = ADD_SUB_CC(a, b, 1);
		break;

	/* and X */
	case 0x20:
		R8[A] = F_C(a & b, 1);
		SF(CF, 0);
		break;

	/* xor X */
	case 0x28:
		R8[A] = F_C(a ^ b, 0);
		SF(CF, 0);
		break;

	/* or X */
	case 0x30:
		R8[A] = F_C(a | b, 0);
		SF(CF, 0);
		break;

	/* cp X */
	case 0x38:
		ADD_SUB_C(a, b, 1);
		YX(b);
		break;
	}

	return Z80_OP_GOOD;
}
static const char *aln[] = { "add", "adc", "sub", "sbc", "and", "xor", "or", "cp" };
#define ALN aln[(op >> 3) & 7]

static void
iof (struct z80 *z, uint8_t a)
{
	SF(HF, (a + ((R8[C] - 1) & 0xff)) > 0xff);
	//SF(PF, P8((a + ((R8[C] - 1) & 0xff)) & 0x07) ^ R8[B]); // no neviem
	//YX(a); // no neviem
	SF(NF, BIT(a, 7)); // no neviem
	SF(CF, GF(HF));
	SF(ZF, --R8[B] == 0x00);
	//SF(SF, R8[B] & 0x80); // no neviem
}
#define IOF(a) iof(z,a)

static enum z80_result
do_ed (struct z80 *z, enum z80_flags flags, int column)
{
	uint32_t tmp;
	uint8_t op;

	FETCH_OP

	switch (op) {
	/* ld i,a */
	case 0x47:
		DIS("ld i, a")
		R8[I] = R8[A];
		return Z80_OP_GOOD;

	/* ld r,a */
	case 0x4f:
		DIS("ld r, a")
		R8[R] = R8[A];
		return Z80_OP_GOOD;

	/* ld a,i */
	case 0x57:
		DIS("ld a, i")
		R8[A] = R8[I];
		SF(SF, !!(R8[A] & 0x80));
		SF(ZF, !(R8[A] & 0xff));
		SF(HF, 0);
		SF(PF, z->iff2);
		SF(NF, 0);
		return Z80_OP_GOOD;

	/* ld a,r */
	case 0x5f:
		DIS("ld a, r")
		R8[A] = R8[R];
		SF(SF, !!(R8[A] & 0x80));
		SF(ZF, !(R8[A] & 0xff));
		SF(HF, 0);
		SF(PF, z->iff2);
		SF(NF, 0);
		return Z80_OP_GOOD;

	/* rrd */
	case 0x67:
		DIS("rrd")
		tmp = RD8(R16[HL]);
		WR8(R16[HL], (tmp >> 4) + ((R8[A] & 0x0f) << 4));
		R8[A] = F((R8[A] & 0xf0) + (tmp & 0x0f), 0);
		return Z80_OP_GOOD;

	/* rld */
	case 0x6f:
		DIS("rld")
		tmp = (RD8(R16[HL]) << 4) + (R8[A] & 0x0f);
		WR8(R16[HL], tmp);
		R8[A] = F((R8[A] & 0xf0) + (tmp >> 8), 0);
		return Z80_OP_GOOD;

	/* in f,(c) */
	case 0x70:
		DIS("in f, (c)")
		F(z->in(z, R8[C]), 0);
		return Z80_OP_GOOD;

	/* out (c),0 */
	case 0x71:
		DIS("out (c), 0")
		z->out(z, R8[C], 0); /* Told to vary with CPU */
		return Z80_OP_GOOD;
	}

	switch (op & 0xef) {
	/* cpd/cpdr */
	case 0xa9:
		DIS(REP ? "cpdr" : "cpd")
		tmp = ADD_SUB(R8[A], RD8(R16[HL]--), 1);
		SF(YF, ((tmp - GF(HF)) & 0x02));
		SF(XF, ((tmp - GF(HF)) & 0x08));
		SF(PF, --R16[BC] != 0);
		if (REP && R16[BC] && !GF(ZF)) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* cpi/cpir */
	case 0xa1:
		DIS(REP ? "cpir" : "cpi")
		tmp = ADD_SUB(R8[A], RD8(R16[HL]++), 1);
		SF(YF, ((tmp - GF(HF)) & 0x02));
		SF(XF, ((tmp - GF(HF)) & 0x08));
		SF(PF, --R16[BC] != 0);
		if (REP && R16[BC] && !GF(ZF)) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* ind/indr */
	case 0xaa:
		DIS(REP ? "indr" : "ind")
		tmp = z->in(z, R8[C]);
		WR8(R16[HL], tmp);
		IOF(tmp);
		R16[HL]--;
		if (REP && R8[B]) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* ini/inir */
	case 0xa2:
		DIS(REP ? "inir" : "ini")
		tmp = z->in(z, R8[C]);
		WR8(R16[HL], tmp);
		IOF(tmp);
		R16[HL]++;
		if (REP && R8[B]) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* ldd/lddr */
	case 0xa8:
		DIS(REP ? "lddr" : "ldd")
		tmp = RD8(R16[HL]--);
		WR8(R16[DE]--, tmp);
		SF(YF, (tmp + R8[A]) & 0x02);
		SF(XF, (tmp + R8[A]) & 0x08);
		SF(HF, 0);
		SF(NF, 0);
		SF(PF, --R16[BC] != 0);
		if (REP && R16[BC]) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* ldi/ldir */
	case 0xa0:
		DIS(REP ? "ldir" : "ldi")
		tmp = RD8(R16[HL]++);
		WR8(R16[DE]++, tmp);
		SF(YF, (tmp + R8[A]) & 0x02);
		SF(XF, (tmp + R8[A]) & 0x08);
		SF(HF, 0);
		SF(NF, 0);
		SF(PF, --R16[BC] != 0);
		if (REP && R16[BC]) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* outd/otdr */
	case 0xab:
		DIS(REP ? "otdr" : "outd")
		tmp = RD8(R16[HL]);
		z->out(z, R8[C], tmp); // xxx make out return int
		IOF(tmp);
		R16[HL]--;
		if (REP && R8[B]) R16[PC] -= 2;
		return Z80_OP_GOOD;

	/* outi/otir */
	case 0xa3:
		DIS(REP ? "otir" : "outi")
		tmp = RD8(R16[HL]);
		z->out(z, R8[C], tmp);
		IOF(tmp);
		R16[HL]++;
		if (REP && R8[B]) R16[PC] -= 2;
		return Z80_OP_GOOD;
	}

	switch (op & 0xcf) {
	/* retn */
	case 0x45:
		DIS("retn")
		R16[PC] = RD16(R16[SP]);
		R16[SP] += 2;
		z->iff1 = z->iff2;
		return Z80_OP_GOOD;

	/* reti */
	case 0x4d:
		DIS("reti")
		R16[PC] = RD16(R16[SP]);
		R16[SP] += 2;
		z->iff1 = z->iff2;
		return Z80_OP_GOOD;

	/* sbc hl,Q */
	case 0x42:
		DIS("sbc hl, %s", QN[q24])
		R8[L] = ADD_SUB_C((uint8_t)R8[L], (Q24 & 0xff) + GF(CF), 1);
		R8[H] = ADD_SUB_C((uint8_t)R8[H], (Q24 >> 8) + GF(CF), 1);
		SF(ZF, R16[HL] == 0);
		return Z80_OP_GOOD;

	/* adc hl,Q */
	case 0x4a:
		DIS("adc hl, %s", QN[q24])
		R8[L] = ADD_SUB_C((uint8_t)R8[L], (Q24 & 0xff) + GF(CF), 0);
		R8[H] = ADD_SUB_C((uint8_t)R8[H], (Q24 >> 8) + GF(CF), 0);
		SF(ZF, R16[HL] == 0);
		return Z80_OP_GOOD;

	/* ld (A),Q */
	case 0x43:
		/* ld (A),hl has a better encoding. */
		FETCH16(tmp)
		DIS("ld (0x%04x), %s", tmp, QN[q24])
		WR16(tmp, Q24)
		return Z80_OP_GOOD;

	/* ld Q,(A) */
	case 0x4b:
		/* ld hl,(A) has a better encoding. */
		FETCH16(tmp)
		DIS("ld %s, (0x%04x)", QN[q24], tmp)
		Q24 = RD16(tmp);
		return Z80_OP_GOOD;
	}

	switch (op & 0xc7) {
	/* neg */
	case 0x44:
		DIS("neg")
		R8[A] = ADD_SUB_C(0, (uint8_t)R8[A], 1);
		SF(PF, (uint8_t)R8[A] == 0x80);
		return Z80_OP_GOOD;

	/* in R,(c) */
	case 0x40:
		DIS("in %s, (c)", RN[v33])
		SR(v33, F(z->in(z, R8[C]), 0));
		return Z80_OP_GOOD;

	/* out (c),R */
	case 0x41:
		DIS("out (c), %s", RN[v33])
		z->out(z, R8[C], GR(v33));
		return Z80_OP_GOOD;
	}

	/* im 0 */
	if ((op & 0xd7) == 0x46) {
		DIS("im 0")
		z->im = 0;
		return Z80_OP_GOOD;
	}

	switch (op & 0xdf) {
	/* im 1 */
	case 0x56:
		DIS("im 1")
		z->im = 1;
		return Z80_OP_GOOD;

	/* im 2 */
	case 0x5e:
		DIS("im 2")
		z->im = 2;
		return Z80_OP_GOOD;
	}

	DIS("(bad op)");
	return Z80_OP_BAD;
}

static enum z80_result
do_cb (struct z80 *z, enum z80_flags flags, int column)
{
	uint8_t op;

	FETCH_OP

	switch (op & 0xc0) {
	/* bit B,R */
	case 0x40:
		DIS("bit %d, %s", b33, RN[v30])
		F(GR(v30) & B3, 1);
		return Z80_OP_GOOD;

	/* res B,R */
	case 0x80:
		DIS("res %d, %s", b33, RN[v30])
		SR(v30, GR(v30) & ~(B3));
		return Z80_OP_GOOD;

	/* set B,R */
	case 0xc0:
		DIS("set %d, %s", b33, RN[v30])
		SR(v30, GR(v30) | B3);
		return Z80_OP_GOOD;
	}

	switch (op & 0xf8) {
	/* rlc R */
	case 0x00:
		DIS("rlc %s", RN[v30])
		SR(v30, F_C((GR(v30) << 1) + BR(v30, 7), 0));
		return Z80_OP_GOOD;

	/* rrc R */
	case 0x08:
		DIS("rrc %s", RN[v30])
		SF(CF, BR(v30, 0));
		SR(v30, F(((uint8_t)GR(v30) >> 1) + (GF(CF) << 7), 0));
		return Z80_OP_GOOD;

	/* rl R */
	case 0x10:
		DIS("rl %s", RN[v30])
		SR(v30, F_C((GR(v30) << 1) + GF(CF), 0));
		return Z80_OP_GOOD;

	/* rr R */
	case 0x18:
		DIS("rr %s", RN[v30])
		SR(v30, F_C(((uint8_t)GR(v30) + (GF(CF) << 8) + (BR(v30, 0) << 9)) >> 1, 0));
		return Z80_OP_GOOD;

	/* sla R */
	case 0x20:
		DIS("sla %s", RN[v30])
		SF(CF, BR(v30, 7));
		SR(v30, F(GR(v30) << 1, 0));
		return Z80_OP_GOOD;

	/* sra R */
	case 0x28:
		DIS("sra %s", RN[v30])
		SF(CF, BR(v30, 0));
		SR(v30, F((int8_t)GR(v30) >> 1, 0));
		return Z80_OP_GOOD;

	/* sll R */
	case 0x30:
		DIS("sll %s", RN[v30])
		SF(CF, BR(v30, 7));
		SR(v30, F((GR(v30) << 1) + 1, 0));
		return Z80_OP_GOOD;

	/* srl R */
	case 0x38:
		DIS("srl %s", RN[v30])
		SF(CF, BR(v30, 0));
		SR(v30, F((uint8_t)GR(v30) >> 1, 0));
		return Z80_OP_GOOD;
	}

	DIS("(bad op)");
	return Z80_OP_BAD;
}

static enum z80_result
do_fd (struct z80 *z, enum z80_flags flags, int column)
{
	uint8_t op;

	FETCH_OP

	switch (op) {
	/* ld iyh,iyl */
	case 0x65:
		DIS("ld iyh, iyl")
		R8[IYH] = R8[IYL];
		return Z80_OP_GOOD;

	/* ld iyl,iyh */
	case 0x6c:
		DIS("ld iyl, iyh")
		R8[IYL] = R8[IYH];
		return Z80_OP_GOOD;
	}

	DIS("(bad op)");
	return Z80_OP_BAD;
}

static enum z80_result
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
		return Z80_OP_GOOD;

	/* set B,(I+D) */
	case 0xc6:
		DIS("set %d, (%s+%d)", b33, IN[i5], d8)
		WR8(IPD, RD8(IPD) | B3);
		return Z80_OP_GOOD;
	}

	switch (op & 0xc0) {
	/* bit B,(I+D) */
	case 0x40:
		DIS("bit %d, (%s+%d)", b33, IN[i5], d8)
		F(RD8(IPD) & B3, 1);
		YX(RD8(IPD + 1));
		return Z80_OP_GOOD;

	/* res B,(I+D)->R */
	case 0x80:
		DIS("res %d, (%s+%d->%s)", b33, IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, RD8(IPD) & ~(B3)));
		return Z80_OP_GOOD;

	/* set B,(I+D)->R */
	case 0xc0:
		DIS("set %d, (%s+%d->%s)", b33, IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, RD8(IPD) | B3));
		return Z80_OP_GOOD;
	}

	switch (op) {
	/* rl (I+D) */
	case 0x16:
		DIS("rl (%s+%d)", IN[i5], d8)
		WR8(IPD, F_C((RD8(IPD) << 1) + GF(CF), 0));
		return Z80_OP_GOOD;

	/* rlc (I+D) */
	case 0x06:
		DIS("rlc (%s+%d)", IN[i5], d8)
		WR8(IPD, F_C((RD8(IPD) << 1) + BIT(RD8(IPD), 7), 0));
		return Z80_OP_GOOD;

	/* rr (I+D) */
	case 0x1e:
		DIS("rr (%s+%d)", IN[i5], d8)
		WR8(IPD, F_C((RD8(IPD) + (GF(CF) << 8) + (BIT(RD8(IPD), 0) << 9)) >> 1, 0));
		return Z80_OP_GOOD;

	/* rrc (I+D) */
	case 0x0e:
		DIS("rrc (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, F((RD8(IPD) >> 1) + (GF(CF) << 7), 0));
		return Z80_OP_GOOD;

	/* sla (I+D) */
	case 0x26:
		DIS("sla (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, F(RD8(IPD) << 1, 0));
		return Z80_OP_GOOD;

	/* sra (I+D) */
	case 0x2e:
		DIS("sra (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, F((int8_t)RD8(IPD) >> 1, 0));
		return Z80_OP_GOOD;

	/* sll (I+D) */
	case 0x36:
		DIS("sll (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, F((RD8(IPD) << 1) + 1, 0));
		return Z80_OP_GOOD;

	/* srl (I+D) */
	case 0x3e:
		DIS("srl (%s+%d)", IN[i5], d8)
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, F(RD8(IPD) >> 1, 0));
		return Z80_OP_GOOD;
	}

	switch (op & 0xf8) {
	/* rl (I+D)->R */
	case 0x10:
		DIS("rl (%s+%d->%s)", IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, F_C((RD8(IPD) << 1) + GF(CF), 0)));
		return Z80_OP_GOOD;

	/* rlc (I+D)->R */
	case 0x00:
		DIS("rlc (%s+%d->%s)", IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, F_C((RD8(IPD) << 1) + BIT(RD8(IPD), 7), 0)));
		return Z80_OP_GOOD;

	/* rr (I+D)->R */
	case 0x18:
		DIS("rr (%s+%d->%s)", IN[i5], d8, RN[v30])
		WR8(IPD, SR(v30, F_C((RD8(IPD) + (GF(CF) << 8) + (BIT(RD8(IPD), 0) << 9)) >> 1, 0)));
		return Z80_OP_GOOD;

	/* rrc (I+D)->R */
	case 0x08:
		DIS("rrc (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, SR(v30, F((RD8(IPD) >> 1) + (GF(CF) << 7), 0)));
		return Z80_OP_GOOD;

	/* sla (I+D)->R */
	case 0x20:
		DIS("sla (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, SR(v30, F(RD8(IPD) << 1, 0)));
		return Z80_OP_GOOD;

	/* sra (I+D)->R */
	case 0x28:
		DIS("sra (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, SR(v30, F((int8_t)RD8(IPD) >> 1, 0)));
		return Z80_OP_GOOD;

	/* sll (I+D)->R */
	case 0x30:
		DIS("sll (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 7));
		WR8(IPD, SR(v30, F((RD8(IPD) << 1) + 1, 0)));
		return Z80_OP_GOOD;

	/* srl (I+D)->R */
	case 0x38:
		DIS("srl (%s+%d->%s)", IN[i5], d8, RN[v30])
		SF(CF, BIT(RD8(IPD), 0));
		WR8(IPD, SR(v30, F(RD8(IPD) >> 1, 0)));
		return Z80_OP_GOOD;
	}

	DIS("(bad op)");
	return Z80_OP_BAD;
}

static enum z80_result
do_idd (struct z80 *z, enum z80_flags flags, int column, uint8_t op0)
{
	uint8_t op, n8;
	uint32_t tmp;
	int8_t d8;

	FETCH_OP

	switch (op) {
	/* ld I,A */
	case 0x21:
		FETCH16(tmp)
		DIS("ld %s, 0x%04x", IN[i5], tmp)
		I5 = tmp;
		return Z80_OP_GOOD;

	/* ld (A),I */
	case 0x22:
		FETCH16(tmp)
		DIS("ld (0x%04x), %s", tmp, IN[i5])
		WR16(tmp, I5);
		return Z80_OP_GOOD;

	/* inc I */
	case 0x23:
		DIS("inc %s", IN[i5])
		I5 += 1;
		return Z80_OP_GOOD;

	/* ld I,(A) */
	case 0x2a:
		FETCH16(tmp)
		DIS("ld %s, (0x%04x)", IN[i5], tmp)
		I5 = RD16(tmp);
		return Z80_OP_GOOD;

	/* dec I */
	case 0x2b:
		DIS("dec %s", IN[i5])
		I5 -= 1;
		return Z80_OP_GOOD;

	/* inc (I+D) */
	case 0x34:
		FETCH(d8)
		DIS("inc (%s+%d)", IN[i5], d8)
		WR8(IPD, ADD_SUB(RD8(IPD), 1, 0));
		return Z80_OP_GOOD;

	/* dec (I+D) */
	case 0x35:
		FETCH(d8)
		DIS("dec (%s+%d)", IN[i5], d8)
		WR8(IPD, ADD_SUB(RD8(IPD), 1, 1));
		return Z80_OP_GOOD;

	/* ld (I+D),N */
	case 0x36:
		FETCH(d8)
		FETCH(n8)
		DIS("ld (%s+%d), 0x%02x", IN[i5], d8, n8)
		WR8(IPD, n8);
		return Z80_OP_GOOD;

	/* pop I */
	case 0xe1:
		DIS("pop %s", IN[i5])
		I5 = RD16(R16[SP]);
		R16[SP] += 2;
		return Z80_OP_GOOD;

	/* ex (sp),I */
	case 0xe3:
		DIS("ex (sp), %s", IN[i5])
		tmp = RD16(R16[SP]);
		WR16(R16[SP], I5)
		I5 = tmp;
		return Z80_OP_GOOD;

	/* push I */
	case 0xe5:
		DIS("push %s", IN[i5])
		R16[SP] -= 2;
		WR16(R16[SP], I5)
		return Z80_OP_GOOD;

	/* jp (I) */
	case 0xe9:
		DIS("jp (%s)", IN[i5])
		R16[PC] = I5;
		return Z80_OP_GOOD;

	/* ld sp,I */
	case 0xf9:
		DIS("ld sp, %s", IN[i5])
		R16[SP] = I5;
		return Z80_OP_GOOD;
	case 0xcb:
		/* Extended */
		return do_idd_cb (z, flags, column, op0);
	}

	switch (op & 0xc7) {
	/* ld R,(I+D) */
	case 0x46:
		FETCH(d8)
		DIS("ld %s, (%s+%d)", RN[v33], IN[i5], d8)
		SR(v33, RD8(IPD));
		return Z80_OP_GOOD;

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
		return Z80_OP_GOOD;
	}

	switch (op & 0xf7) {
	/* inc J */
	case 0x24:
		DIS("inc %s", JN[i5b3])
		I5B3 = ADD_SUB(I5B3, 1, 0);
		return Z80_OP_GOOD;

	/* dec J */
	case 0x25:
		DIS("dec %s", JN[i5b3])
		I5B3 = ADD_SUB(I5B3, 1, 1);
		return Z80_OP_GOOD;
	}

	/* add I,Q */
	if ((op & 0xcf) == 0x09) {
		DIS("add %s, %s", IN[i5], XN24)
		tmp = I5 + X24;
		YX_C(tmp >> 8);
		SF(HF, !!((I5 & 0xf00) > (tmp & 0xf00)));
		I5 = tmp;
		return Z80_OP_GOOD;
	}

	/* ld J,R */
	if ((op & 0xf0) == 0x60) {
		DIS("ld %s, %s", JN[i5b3], RN[v30])
		I5B3 = GR(v30);
		return Z80_OP_GOOD;
	}

	switch (op & 0xc6) {
	/* ld R,J */
	case 0x44:
		DIS("ld %s, %s", RN[v33], JN[i5b0])
		SR(v33, I5B0);
		return Z80_OP_GOOD;

	/* <al> a,J */
	case 0x84:
		DIS("%s a, %s", ALN, JN[i5b0])
		return do_al (z, flags, column, op, I5B0);
	}

	if (op0 == 0xdd) {
		switch (op) {
		/* ld ixh,ixl */
		case 0x65:
			DIS("ld ixh, ixl")
			R8[IXH] = R8[IXL];
			return Z80_OP_GOOD;

		/* ld ixl,ixh */
		case 0x6c:
			DIS("ld ixl, ixh")
			R8[IXL] = R8[IXH];
			return Z80_OP_GOOD;
		}
	}

	DIS("(bad op)");
	return Z80_OP_BAD;
}

enum z80_result
z80_insn (struct z80 *z, enum z80_flags flags)
{
	int column = 0;
	uint8_t n8, op;
	uint32_t tmp;
	int8_t d8;

	if (PRINT_REGS)
		print_regs (z, PRTO, ' ');

	if (PRINT_ADDR)
		fprintf (PRTO, "%04x: ", R16[PC]);

	FETCH_OP

	switch (op) {
	/* nop */
	case 0x00:
		DIS("nop")
		/* nothing */;
		return Z80_OP_GOOD;

	/* ld (bc),a */
	case 0x02:
		DIS("ld (bc), a")
		WR8(R16[BC], R8[A]);
		return Z80_OP_GOOD;

	/* ld a,(bc) */
	case 0x0a:
		DIS("ld a, (bc)")
		R8[A] = RD8(R16[BC]);
		return Z80_OP_GOOD;

	/* ld (de),a */
	case 0x12:
		DIS("ld (de), a")
		WR8(R16[DE], R8[A]);
		return Z80_OP_GOOD;

	/* ld a,(de) */
	case 0x1a:
		DIS("ld a, (de)")
		R8[A] = RD8(R16[DE]);
		return Z80_OP_GOOD;

	/* halt */
	case 0x76:
		DIS("halt")
		/* wait for interrupt */;
		return Z80_OP_HALT;

	/* ret */
	case 0xc9:
		DIS("ret")
		R16[PC] = RD16(R16[SP]);
		R16[SP] += 2;
		return Z80_OP_GOOD;

	/* exx */
	case 0xd9:
		DIS("exx")
		XCHG(R16[BC], R16[BC_]);
		XCHG(R16[DE], R16[DE_]);
		XCHG(R16[HL], R16[HL_]);
		return Z80_OP_GOOD;

	/* ex (sp),hl */
	case 0xe3:
		DIS("ex (sp), hl")
		tmp = RD16(R16[SP]);
		WR16(R16[SP], R16[HL])
		R16[HL] = tmp;
		return Z80_OP_GOOD;

	/* jp (hl) */
	case 0xe9:
		DIS("jp (hl)")
		R16[PC] = R16[HL];
		return Z80_OP_GOOD;

	/* ex de,hl */
	case 0xeb:
		DIS("ex de, hl")
		XCHG(R16[DE], R16[HL]);
		return Z80_OP_GOOD;

	/* di */
	case 0xf3:
		DIS("di")
		z->iff1 = 0;
		z->iff2 = 0;
		return Z80_OP_GOOD;

	/* ld sp,hl */
	case 0xf9:
		DIS("ld sp, hl")
		R16[SP] = R16[HL];
		return Z80_OP_GOOD;

	/* ei */
	case 0xfb:
		DIS("ei")
		z->iff2 = 1; /* FIXME: after the next instruction */
		return Z80_OP_GOOD;

	/* djnz E */
	case 0x10:
		FETCH(d8)
		DIS("djnz %d", d8)
		if (R8[B] -= 1) R16[PC] += d8;
		return Z80_OP_GOOD;

	/* jr E */
	case 0x18:
		FETCH(d8)
		DIS("jr %d", d8)
		R16[PC] += d8;
		return Z80_OP_GOOD;

	/* jr nz,E */
	case 0x20:
		FETCH(d8)
		DIS("jr nz, %d", d8)
		if (!GF(ZF)) R16[PC] += d8;
		return Z80_OP_GOOD;

	/* jr z,E */
	case 0x28:
		FETCH(d8)
		DIS("jr z, %d", d8)
		if (GF(ZF)) R16[PC] += d8;
		return Z80_OP_GOOD;

	/* jr nc,E */
	case 0x30:
		FETCH(d8)
		DIS("jr nc, %d", d8)
		if (!GF(CF)) R16[PC] += d8;
		return Z80_OP_GOOD;

	/* jr c,E */
	case 0x38:
		FETCH(d8)
		DIS("jr c, %d", d8)
		if (GF(CF)) R16[PC] += d8;
		return Z80_OP_GOOD;

	/* out (N),a */
	case 0xd3:
		FETCH(n8)
		DIS("out (0x%02x), a", n8)
		z->out(z, n8, R8[A]);
		return Z80_OP_GOOD;

	/* in a,(N) */
	case 0xdb:
		FETCH(n8)
		DIS("in a, (0x%02x)", n8)
		R8[A] = z->in(z, n8);
		return Z80_OP_GOOD;

	/* ld (A),hl */
	case 0x22:
		FETCH16(tmp)
		DIS("ld (0x%04x), hl", tmp)
		WR16(tmp, R16[HL]);
		return Z80_OP_GOOD;

	/* ld hl,(A) */
	case 0x2a:
		FETCH16(tmp)
		DIS("ld hl, (0x%04x)", tmp)
		R16[HL] = RD16(tmp);
		return Z80_OP_GOOD;

	/* ld (A),a */
	case 0x32:
		FETCH16(tmp)
		DIS("ld (0x%04x), a", tmp)
		WR8(tmp, R8[A]);
		return Z80_OP_GOOD;

	/* ld a,(A) */
	case 0x3a:
		FETCH16(tmp)
		DIS("ld a, (0x%04x)", tmp)
		R8[A] = RD8(tmp);
		return Z80_OP_GOOD;

	/* jp A */
	case 0xc3:
		FETCH16(tmp)
		DIS("jp 0x%04x", tmp)
		R16[PC] = tmp;
		return Z80_OP_GOOD;

	/* call A */
	case 0xcd:
		FETCH16(tmp)
		DIS("call 0x%04x", tmp)
		R16[SP] -= 2;
		WR16(R16[SP], R16[PC])
		R16[PC] = tmp;
		return Z80_OP_GOOD;

	/* ex af,af' */
	case 0x08:
		DIS("ex af, af'")
		XCHG(R16[AF], R16[AF_]);
		return Z80_OP_GOOD;

	/* rlca */
	case 0x07:
		DIS("rlca")
		R8[A] = YX_C((R8[A] << 1) + BIT(R8[A], 7));
		SF(HF, 0);
		return Z80_OP_GOOD;

	/* rra */
	case 0x1f:
		DIS("rra")
		R8[A] = YX_C(((BIT(R8[A], 0) << 9) + (GF(CF) << 8) + (uint8_t)R8[A]) >> 1);
		SF(HF, 0);
		return Z80_OP_GOOD;

	/* rrca */
	case 0x0f:
		DIS("rrca")
		R8[A] = YX_C(((BIT(R8[A], 0) << 9) + (BIT(R8[A], 0) << 8) + (uint8_t)R8[A]) >> 1);
		SF(HF, 0);
		return Z80_OP_GOOD;

	/* rla */
	case 0x17:
		DIS("rla")
		R8[A] = YX_C((R8[A] << 1) + GF(CF));
		SF(HF, 0);
		return Z80_OP_GOOD;

	/* daa */
	case 0x27:
		DIS("daa")
		tmp = R8[A];
		if (GF(HF) || (R8[A] & 0x0f) > 9)
			tmp += (GF(NF) ? -0x06 : 0x06);
		if (GF(CF) || (uint8_t)R8[A] > 0x99)
			tmp += (GF(NF) ? -0x60 : 0x60);
		SZYHX(tmp, BIT(R8[A], 4) ^ BIT(tmp, 4));
		SF(PF, P8(tmp));
		if ((uint8_t)R8[A] > 0x99)
			SF(CF, 1);
		R8[A] = tmp;
		return Z80_OP_GOOD;

	/* cpl */
	case 0x2f:
		DIS("cpl")
		R8[A] = YX(~(R8[A]));
		SF(HF, 1);
		SF(NF, 1);
		return Z80_OP_GOOD;

	/* scf */
	case 0x37:
		DIS("scf")
		YX(R8[A]);
		SF(HF, 0);
		SF(NF, 0);
		SF(CF, 1);
		return Z80_OP_GOOD;

	/* ccf */
	case 0x3f:
		DIS("ccf")
		YX(R8[A] | R8[F]);
		SF(HF, GF(CF));
		SF(NF, 0);
		SF(CF, !GF(CF));
		return Z80_OP_GOOD;
	}

	/* Extended instructions. */
	if ((op & 0xdf) == 0xdd) {
		return do_idd (z, flags, column, op);
	}
	switch (op) {
	case 0xed:
		return do_ed (z, flags, column);
	case 0xcb:
		return do_cb (z, flags, column);
	case 0xfd:
		return do_fd (z, flags, column);
	}

	switch (op & 0xcf) {
	/* inc Q */
	case 0x03:
		DIS("inc %s", QN[q24])
		Q24 += 1;
		return Z80_OP_GOOD;

	/* add hl,Q */
	case 0x09:
		DIS("add hl, %s", QN[q24])
		tmp = R16[HL] + Q24;
		YX_C(tmp >> 8);
		SF(HF, !!((R16[HL] & 0xf00) > (tmp & 0xf00)));
		R16[HL] = tmp;
		return Z80_OP_GOOD;

	/* dec Q */
	case 0x0b:
		DIS("dec %s", QN[q24])
		Q24 -= 1;
		return Z80_OP_GOOD;
	}

	switch (op & 0xc7) {
	/* inc R */
	case 0x04:
		DIS("inc %s", RN[v33])
		SR(v33, ADD_SUB(GR(v33), 1, 0));
		return Z80_OP_GOOD;

	/* dec R */
	case 0x05:
		DIS("dec %s", RN[v33])
		SR(v33, ADD_SUB(GR(v33), 1, 1));
		return Z80_OP_GOOD;

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
		return Z80_OP_GOOD;

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
		return Z80_OP_GOOD;

	/* push P */
	case 0xc5:
		DIS("push %s", PN[p24])
		R16[SP] -= 2;
		WR16(R16[SP], P24)
		return Z80_OP_GOOD;
	}

	switch (op & 0xc7) {
	/* ld R,N */
	case 0x06:
		FETCH(n8)
		DIS("ld %s, 0x%02x", RN[v33], n8)
		SR(v33, n8);
		return Z80_OP_GOOD;

	/* jp C,A */
	case 0xc2:
		FETCH16(tmp)
		DIS("jp %s, 0x%04x", CN[v33], tmp)
		if (COND) R16[PC] = tmp;
		return Z80_OP_GOOD;

	/* call C,A */
	case 0xc4:
		FETCH16(tmp)
		DIS("call %s, 0x%04x", CN[v33], tmp)
		if (COND) {
			R16[SP] -= 2;
			WR16(R16[SP], R16[PC])
			R16[PC] = tmp;
		}
		return Z80_OP_GOOD;

	/* ret C */
	case 0xc0:
		DIS("ret %s", CN[v33])
		if (COND) {
			R16[PC] = RD16(R16[SP]);
			R16[SP] += 2;
		}
		return Z80_OP_GOOD;

	/* rst S */
	case 0xc7:
		DIS("rst %d", S)
		R16[SP] -= 2;
		WR16(R16[SP], R16[PC])
		R16[PC] = S;
		return Z80_OP_GOOD;
	}

	/* ld Q,A */
	if ((op & 0xcf) == 0x01) {
		FETCH16(tmp)
		DIS("ld %s, 0x%04x", QN[q24], tmp)
		Q24 = tmp;
		return Z80_OP_GOOD;
	}

	DIS("(bad op)");
	return Z80_OP_BAD;
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
