/*
 * Copyright (C) 2024 Mikulas Patocka
 *
 * This file is part of Ajla.
 *
 * Ajla is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * Ajla is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Ajla. If not, see <https://www.gnu.org/licenses/>.
 */

typedef uint64_t it;

#define USE_BRCL		Z

#define S390_BCR		0x070000000000ULL
#define S390_BASR		0x0d0000000000ULL

#define S390_LTR		0x120000000000ULL
#define S390_LTGR		0xb90200000000ULL

#define S390_LCR		0x130000000000ULL
#define S390_LCGR		0xb90300000000ULL

#define S390_NR			0x140000000000ULL
#define S390_NRK		0xb9f400000000ULL
#define S390_N			0x540000000000ULL
#define S390_NY			0xe30000000054ULL
#define S390_NGR		0xb98000000000ULL
#define S390_NGRK		0xb9e400000000ULL
#define S390_NG			0xe30000000080ULL
#define S390_NILL		0xa50700000000ULL
#define S390_NILH		0xa50600000000ULL
#define S390_NIHL		0xa50500000000ULL
#define S390_NIHH		0xa50400000000ULL
#define S390_NILF		0xc00b00000000ULL
#define S390_NIHF		0xc00a00000000ULL

#define S390_CLR		0x150000000000ULL
#define S390_CL			0x550000000000ULL
#define S390_CLY		0xe30000000055ULL
#define S390_CLGR		0xb92100000000ULL
#define S390_CLG		0xe30000000021ULL

#define S390_OR			0x160000000000ULL
#define S390_ORK		0xb9f600000000ULL
#define S390_O			0x560000000000ULL
#define S390_OY			0xe30000000056ULL
#define S390_OGR		0xb98100000000ULL
#define S390_OGRK		0xb9e600000000ULL
#define S390_OG			0xe30000000081ULL
#define S390_OILL		0xa50b00000000ULL
#define S390_OILH		0xa50a00000000ULL
#define S390_OIHL		0xa50900000000ULL
#define S390_OIHH		0xa50800000000ULL
#define S390_OILF		0xc00d00000000ULL
#define S390_OIHF		0xc00c00000000ULL

#define S390_XR			0x170000000000ULL
#define S390_XRK		0xb9f700000000ULL
#define S390_X			0x570000000000ULL
#define S390_XY			0xe30000000057ULL
#define S390_XGR		0xb98200000000ULL
#define S390_XGRK		0xb9e700000000ULL
#define S390_XG			0xe30000000082ULL
#define S390_XILF		0xc00700000000ULL
#define S390_XIHF		0xc00600000000ULL

#define S390_LR			0x180000000000ULL
#define S390_L			0x580000000000ULL
#define S390_LY			0xe30000000058ULL
#define S390_LGR		0xb90400000000ULL
#define S390_LG			0xe30000000004ULL
#define S390_LHI		0xa70800000000ULL
#define S390_LGHI		0xa70900000000ULL
#define S390_LGFI		0xc00100000000ULL
#define S390_LGFR		0xb91400000000ULL
#define S390_LLGCR		0xb98400000000ULL
#define S390_LLGC		0xe30000000090ULL
#define S390_LLGHR		0xb98500000000ULL
#define S390_LLGH		0xe30000000091ULL
#define S390_LLGFR		0xb91600000000ULL
#define S390_LBR		0xb92600000000ULL
#define S390_LB			0xe30000000076ULL
#define S390_LGBR		0xb90600000000ULL
#define S390_LGB		0xe30000000077ULL

#define S390_CR			0x190000000000ULL
#define S390_C			0x590000000000ULL
#define S390_CY			0xe30000000059ULL
#define S390_CGR		0xb92000000000ULL
#define S390_CG			0xe30000000020ULL
#define S390_CHI		0xa70e00000000ULL
#define S390_CGHI		0xa70f00000000ULL

#define S390_AR			0x1a0000000000ULL
#define S390_ARK		0xb9f800000000ULL
#define S390_A			0x5a0000000000ULL
#define S390_AY			0xe3000000005aULL
#define S390_AGR		0xb90800000000ULL
#define S390_AGRK		0xb9e800000000ULL
#define S390_AG			0xe30000000008ULL
#define S390_AHI		0xa70a00000000ULL
#define S390_AGHI		0xa70b00000000ULL
#define S390_AGF		0xe30000000018ULL

#define S390_SR			0x1b0000000000ULL
#define S390_SRK		0xb9f900000000ULL
#define S390_S			0x5b0000000000ULL
#define S390_SY			0xe3000000005bULL
#define S390_SGR		0xb90900000000ULL
#define S390_SGRK		0xb9e900000000ULL
#define S390_SG			0xe30000000009ULL

#define S390_MR			0x1c0000000000ULL
#define S390_M			0x5c0000000000ULL
#define S390_MFY		0xe3000000005cULL
#define S390_MGRK		0xb9ec00000000ULL
#define S390_MG			0xe30000000084ULL
#define S390_MSR		0xb25200000000ULL
#define S390_MS			0x710000000000ULL
#define S390_MSY		0xe30000000051ULL
#define S390_MSRKC		0xb9fd00000000ULL
#define S390_MSC		0xe30000000053ULL
#define S390_MSGR		0xb90c00000000ULL
#define S390_MSGRKC		0xb9ed00000000ULL
#define S390_MSG		0xe3000000000cULL
#define S390_MSGC		0xe30000000083ULL

#define S390_DR			0x1d0000000000ULL
#define S390_DLR		0xb99700000000ULL
#define S390_DLGR		0xb98700000000ULL
#define S390_DSGR		0xb90d00000000ULL

#define S390_ALR		0x1e0000000000ULL
#define S390_ALRK		0xb9fa00000000ULL
#define S390_AL			0x5e0000000000ULL
#define S390_ALY		0xe3000000005eULL
#define S390_ALGR		0xb90a00000000ULL
#define S390_ALGRK		0xb9ea00000000ULL
#define S390_ALG		0xe3000000000aULL

#define S390_SLR		0x1f0000000000ULL
#define S390_SLRK		0xb9fb00000000ULL
#define S390_SL			0x5f0000000000ULL
#define S390_SLY		0xe3000000005fULL
#define S390_SLGR		0xb90b00000000ULL
#define S390_SLGRK		0xb9eb00000000ULL
#define S390_SLG		0xe3000000000bULL

#define S390_LER		0x380000000000ULL
#define S390_LDR		0x280000000000ULL
#define S390_LXR		0xb36500000000ULL
#define S390_LE			0x780000000000ULL
#define S390_LEY		0xed0000000064ULL
#define S390_LD			0x680000000000ULL
#define S390_LDY		0xed0000000065ULL

#define S390_STE		0x700000000000ULL
#define S390_STEY		0xed0000000066ULL
#define S390_STD		0x600000000000ULL
#define S390_STDY		0xed0000000067ULL

#define S390_LA			0x410000000000ULL
#define S390_LAY		0xe30000000071ULL

#define S390_STC		0x420000000000ULL
#define S390_STCY		0xe30000000072ULL
#define S390_STH		0x400000000000ULL
#define S390_STHY		0xe30000000070ULL
#define S390_ST			0x500000000000ULL
#define S390_STY		0xe30000000050ULL
#define S390_STG		0xe30000000024ULL

#define S390_IC			0x430000000000ULL
#define S390_ICY		0xe30000000073ULL

#define S390_LCEBR		0xb30300000000ULL
#define S390_LCDBR		0xb31300000000ULL
#define S390_LCXBR		0xb34300000000ULL

#define S390_CEBR		0xb30900000000ULL
#define S390_CDBR		0xb31900000000ULL
#define S390_CXBR		0xb34900000000ULL
#define S390_CEB		0xed0000000009ULL
#define S390_CDB		0xed0000000019ULL

#define S390_AEBR		0xb30a00000000ULL
#define S390_ADBR		0xb31a00000000ULL
#define S390_AXBR		0xb34a00000000ULL
#define S390_AEB		0xed000000000aULL
#define S390_ADB		0xed000000001aULL

#define S390_SEBR		0xb30b00000000ULL
#define S390_SDBR		0xb31b00000000ULL
#define S390_SXBR		0xb34b00000000ULL
#define S390_SEB		0xed000000000bULL
#define S390_SDB		0xed000000001bULL

#define S390_DEBR		0xb30d00000000ULL
#define S390_DDBR		0xb31d00000000ULL
#define S390_DXBR		0xb34d00000000ULL
#define S390_DEB		0xed000000000dULL
#define S390_DDB		0xed000000001dULL

#define S390_SQEBR		0xb31400000000ULL
#define S390_SQDBR		0xb31500000000ULL
#define S390_SQXBR		0xb31600000000ULL
#define S390_SQEB		0xed0000000014ULL
#define S390_SQDB		0xed0000000015ULL

#define S390_MEEBR		0xb31700000000ULL
#define S390_MDBR		0xb31c00000000ULL
#define S390_MXBR		0xb34c00000000ULL
#define S390_MEEB		0xed0000000017ULL
#define S390_MDB		0xed000000001cULL

#define S390_FIEBR		0xb35700000000ULL
#define S390_FIDBR		0xb35f00000000ULL
#define S390_FIXBR		0xb34700000000ULL

#define S390_CEFBR		0xb39400000000ULL
#define S390_CDFBR		0xb39500000000ULL
#define S390_CXFBR		0xb39600000000ULL
#define S390_CEGBR		0xb3a400000000ULL
#define S390_CDGBR		0xb3a500000000ULL
#define S390_CXGBR		0xb3a600000000ULL

#define S390_CFEBR		0xb39800000000ULL
#define S390_CFDBR		0xb39900000000ULL
#define S390_CFXBR		0xb39a00000000ULL
#define S390_CGEBR		0xb3a800000000ULL
#define S390_CGDBR		0xb3a900000000ULL
#define S390_CGXBR		0xb3aa00000000ULL

#define S390_LHR		0xb92700000000ULL
#define S390_LH			0x480000000000ULL
#define S390_LHY		0xe30000000078ULL
#define S390_LGHR		0xb90700000000ULL
#define S390_LGH		0xe30000000015ULL
#define S390_LGF		0xe30000000014ULL
#define S390_LLGF		0xe30000000016ULL

#define S390_RLL		0xeb000000001dULL
#define S390_RLLG		0xeb000000001cULL
#define S390_SRL		0x880000000000ULL
#define S390_SRLK		0xeb00000000deULL
#define S390_SRLG		0xeb000000000cULL
#define S390_SLL		0x890000000000ULL
#define S390_SLLK		0xeb00000000dfULL
#define S390_SLLG		0xeb000000000dULL
#define S390_SRA		0x8a0000000000ULL
#define S390_SRAK		0xeb00000000dcULL
#define S390_SRAG		0xeb000000000aULL
#define S390_SLA		0x8b0000000000ULL
#define S390_SLAK		0xeb00000000ddULL
#define S390_SLAG		0xeb000000000bULL

#define S390_STM		0x900000000000ULL
#define S390_STMY		0xeb0000000090ULL
#define S390_STMG		0xeb0000000024ULL
#define S390_LM			0x980000000000ULL
#define S390_LMY		0xeb0000000098ULL
#define S390_LMG		0xeb0000000004ULL

#define S390_MVI		0x920000000000ULL
#define S390_MVIY		0xeb0000000052ULL
#define S390_CLI		0x950000000000ULL
#define S390_CLIY		0xeb0000000055ULL

#define S390_TMLL		0xa70100000000ULL
#define S390_TMLH		0xa70000000000ULL
#define S390_TMHL		0xa70300000000ULL
#define S390_TMHH		0xa70200000000ULL

#define S390_BRC		0xa70400000000ULL
#define S390_BRAS		0xa70500000000ULL
#define S390_LRVR		0xb91f00000000ULL
#define S390_LRVRG		0xb90f00000000ULL
#define S390_POPCNT		0xb9e180000000ULL
#define S390_LOCR		0xb9f200000000ULL
#define S390_LOCGR		0xb9e200000000ULL
#define S390_NCRK		0xb9f500000000ULL
#define S390_NCGRK		0xb9e500000000ULL
#define S390_LOC		0xeb00000000f2ULL
#define S390_LOCG		0xeb00000000e2ULL
#define S390_BRCL		0xc00400000000ULL
#define  S390_BRC_OVF			0x1ULL
#define  S390_BRC_GREATER		0x2ULL
#define  S390_BRC_LESS			0x4ULL
#define  S390_BRC_EQ			0x8ULL

#define S390_IIHF		0xc00800000000ULL
#define S390_IILF		0xc00900000000ULL

#define S390_MVC		0xd20000000000ULL

struct codes {
	it rr;
	it rrk;
	it rx;
	it rxy;
	it rrg;
	it rrgk;
	it rxg;
	it ri;
	it rig;
	it rig32;
	it rill;
	it rilh;
	it rihl;
	it rihh;
	it rilf;
	it rihf;
	int neg_imm;
};

static const struct codes codes_cmp = { S390_CR, -1, S390_C, S390_CY, S390_CGR, -1, S390_CG, S390_CHI, S390_CGHI, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_cmp_log = { S390_CLR, -1, S390_CL, S390_CLY, S390_CLGR, -1, S390_CLG, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_ic = { -1, -1, S390_IC, S390_ICY, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load_8 = { S390_LBR, -1, -1, S390_LB, S390_LGBR, -1, S390_LGB, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load_16 = { -1, -1, S390_LH, S390_LHY, S390_LGHR, -1, S390_LGH, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load_32 = { -1, -1, -1, -1, S390_LGFR, -1, S390_LGF, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load_8_unsigned = { -1, -1, -1, -1, S390_LLGCR, -1, S390_LLGC, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load_16_unsigned = { -1, -1, -1, -1, S390_LLGHR, -1, S390_LLGH, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load_32_unsigned = { -1, -1, -1, -1, S390_LLGFR, -1, S390_LLGF, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_load = { S390_LR, -1, S390_L, S390_LY, S390_LGR, -1, S390_LG, S390_LHI, S390_LGHI, S390_LGFI, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_store_8 = { -1, -1, S390_STC, S390_STCY, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_store_16 = { -1, -1, S390_STH, S390_STHY, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };
static const struct codes codes_store = { -1, -1, S390_ST, S390_STY, -1, -1, S390_STG, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 };

static const struct codes codes_alu_no_flags[] = {
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ S390_MSR, -1, S390_MS, S390_MSY, S390_MSGR, -1, S390_MSG, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
};

static const struct codes codes_alu[] = {
	{ S390_AR, S390_ARK, S390_A, S390_AY, S390_AGR, S390_AGRK, S390_AG, S390_AHI, S390_AGHI, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ S390_OR, S390_ORK, S390_O, S390_OY, S390_OGR, S390_OGRK, S390_OG, -1, -1, -1, S390_OILL, S390_OILH, S390_OIHL, S390_OIHH, S390_OILF, S390_OIHF, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ S390_NR, S390_NRK, S390_N, S390_NY, S390_NGR, S390_NGRK, S390_NG, -1, -1, -1, S390_NILL, S390_NILH, S390_NIHL, S390_NIHH, S390_NILF, S390_NIHF, 2 },
	{ S390_SR, S390_SRK, S390_S, S390_SY, S390_SGR, S390_SGRK, S390_SG, S390_AHI, S390_AGHI, -1, -1, -1, -1, -1, -1, -1, 1 },
	{ S390_XR, S390_XRK, S390_X, S390_XY, S390_XGR, S390_XGRK, S390_XG, -1, -1, -1, -1, -1, -1, -1, S390_XILF, S390_XIHF, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, S390_NCRK, -1, -1, -1, S390_NCGRK, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, S390_MSRKC, -1, S390_MSC, -1, S390_MSGRKC, S390_MSGC, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
};

static const struct codes codes_alu_log[] = {
	{ S390_ALR, S390_ALRK, S390_AL, S390_ALY, S390_ALGR, S390_ALGRK, S390_ALG, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
	{ S390_SLR, S390_SLRK, S390_SL, S390_SLY, S390_SLGR, S390_SLGRK, S390_SLG, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0 },
};

static const it rot32[9] = {
	S390_RLL, -1, -1, -1,
	S390_SLL, S390_SRL, -1, S390_SRA,
	S390_SLA,
};

static const it rot32k[9] = {
	S390_RLL, -1, -1, -1,
	S390_SLLK, S390_SRLK, -1, S390_SRAK,
	S390_SLAK,
};

static const it rot64[9] = {
	S390_RLLG, -1, -1, -1,
	S390_SLLG, S390_SRLG, -1, S390_SRAG,
	S390_SLAG,
};

static const int8_t jmp_cond[0x30] = {
	S390_BRC_OVF,			S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_EQ,
	-1,				-1,
	S390_BRC_EQ,			S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_OVF,
	-1,				-1,
	-1,				-1,
	-1,				-1,
	S390_BRC_LESS,			S390_BRC_GREATER | S390_BRC_EQ,
	S390_BRC_LESS | S390_BRC_EQ,	S390_BRC_GREATER,

	-1,				-1,
	S390_BRC_OVF | S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_EQ, -1,
	-1,				-1,
	-1,				-1,
	-1,				-1,
	-1,				-1,
	-1,				-1,
	-1,				-1,

	-1,				-1,
	S390_BRC_LESS,			S390_BRC_GREATER | S390_BRC_EQ,
	S390_BRC_EQ,			S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_OVF,
	S390_BRC_LESS | S390_BRC_EQ,	S390_BRC_GREATER,
	-1,				-1,
	S390_BRC_OVF,			S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_EQ,
	-1,				-1,
	-1,				-1,
};

static const int8_t jmp_cond_logical[0x8] = {
	-1,				-1,
	S390_BRC_LESS,			S390_BRC_GREATER | S390_BRC_EQ,
	S390_BRC_EQ,			S390_BRC_GREATER | S390_BRC_LESS,
	S390_BRC_LESS | S390_BRC_EQ,	S390_BRC_GREATER,
};

struct fp_alu {
	it err;
	it drr;
	it xrr;
	it erx;
	it drx;
};

static const struct fp_alu fp_alus[4] = {
	{ S390_AEBR, S390_ADBR, S390_AXBR, S390_AEB, S390_ADB },
	{ S390_SEBR, S390_SDBR, S390_SXBR, S390_SEB, S390_SDB },
	{ S390_MEEBR, S390_MDBR, S390_MXBR, S390_MEEB, S390_MDB },
	{ S390_DEBR, S390_DDBR, S390_DXBR, S390_DEB, S390_DDB },
};

static const struct fp_alu fp_alu1s[3] = {
	{ S390_LCEBR, S390_LCDBR, S390_LCXBR, -1, -1 },
	{ S390_SQEBR, S390_SQDBR, S390_SQXBR, S390_SQEB, S390_SQDB },
	{ S390_FIEBR | 0x40000000, S390_FIDBR | 0x40000000, S390_FIXBR | 0x40000000, -1, -1 },
};

static const struct fp_alu fp_cmp = {
	S390_CEBR, S390_CDBR, S390_CXBR, S390_CEB, S390_CDB
};

static uint8_t get_jmp_cond(unsigned cond, bool logical)
{
	int8_t c;
	if (!logical) {
		if (unlikely(cond >= n_array_elements(jmp_cond)))
			goto invl;
		c = jmp_cond[cond];
	} else {
		if (unlikely(cond >= n_array_elements(jmp_cond_logical)))
			goto invl;
		c = jmp_cond_logical[cond];
	}
	if (unlikely(c == -1))
		goto invl;
	return (uint8_t)c;
invl:
	internal(file_line, "get_jmp_cond: invalid %scondition %x", logical ? "logical " : "", cond);
}

static bool attr_w cgen_s390(struct codegen_context *ctx, it code)
{
	unsigned sz = code >> 46;
	if (sz == 0) {
		if (unlikely((uint32_t)code))
			goto invl;
		cgen_two(code >> 32);
	} else if (sz == 1 || sz == 2) {
		if (unlikely((uint16_t)code))
			goto invl;
		cgen_four(code >> 16);
	} else if (sz == 3) {
		cgen_two(code >> 32);
		cgen_four(code);
	} else {
invl:
		internal(file_line, "cgen_s390: invalid insn %"PRIxMAX"", (uintmax_t)code);
	}
	return true;
}

static bool attr_w cgen_rr_rx(struct codegen_context *ctx, unsigned size, uint8_t *arg1, uint8_t *arg2, uint8_t *arg3, const struct codes *codes)
{
	it code;
	uint8_t b, x;
	uint8_t *disp;
	int64_t imm;
	if (size > OP_SIZE_NATIVE)
		goto invl;
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] >= 0x10))
		goto invl;
	if (arg3[0] < 0x10) {
		unsigned sz;
		bool k = false;
		if (size != OP_SIZE_8) {
			code = codes->rr;
			if (code == (it)-1 || arg1[0] != arg2[0]) {
				code = codes->rrk;
				k = true;
			}
		} else {
			code = codes->rrg;
			if (code == (it)-1 || arg1[0] != arg2[0]) {
				code = codes->rrgk;
				k = true;
			}
		}
		sz = code >> 46;
		if (k) {
			code |= (it)arg1[0] << 20;
			code |= (it)arg2[0] << 16;
			code |= (it)arg3[0] << 28;
		} else if (!sz) {
			code |= (it)arg1[0] << 36;
			code |= (it)arg3[0] << 32;
		} else if (sz == 1 || sz == 2) {
			code |= (it)arg1[0] << 20;
			code |= (it)arg3[0] << 16;
		} else {
			goto invl;
		}
		g(cgen_s390(ctx, code));
		return true;
	}
	if (unlikely(arg1[0] != arg2[0]))
		goto invl;
	if (arg3[0] == ARG_IMM) {
		imm = get_imm(&arg3[1]);
		if (codes->neg_imm == 1)
			imm = -(uint64_t)imm;
		if (imm >= -0x8000 && imm < 0x8000) {
			code = size != OP_SIZE_8 ? codes->ri : codes->rig;
			if (unlikely(code == (it)-1))
				goto log_op;
			code |= (it)arg1[0] << 36;
			code |= (it)(imm & 0xffff) << 16;
		} else if (imm >= -0x80000000LL && imm < 0x80000000LL) {
			code = codes->rig32;
			if (unlikely(code == (it)-1))
				goto log_op;
			code |= (it)arg1[0] << 36;
			code |= (it)(imm & 0xffffffffLL);
		} else {
			goto log_op;
		}
		g(cgen_s390(ctx, code));
		return true;
log_op:
		if (codes->neg_imm == 2)
			imm = ~imm;
		if (!(imm & ~0xffffULL) && codes->rill != (it)-1) {
			code = codes->rill;
			if (codes->neg_imm == 2)
				imm = ~imm;
			code |= (it)(imm & 0xffffULL) << 16;
		} else if (!(imm & ~0xffff0000ULL) && codes->rilh != (it)-1) {
			code = codes->rilh;
			if (codes->neg_imm == 2)
				imm = ~imm;
			code |= (it)(imm & 0xffff0000ULL);
		} else if (!(imm & ~0xffff00000000ULL) && codes->rihl != (it)-1) {
			code = codes->rihl;
			if (codes->neg_imm == 2)
				imm = ~imm;
			code |= (it)((uint64_t)imm & 0xffff00000000ULL) >> 16;
		} else if (!(imm & ~0xffff000000000000ULL) && codes->rihh != (it)-1) {
			code = codes->rihh;
			if (codes->neg_imm == 2)
				imm = ~imm;
			code |= (it)((uint64_t)imm & 0xffff000000000000ULL) >> 32;
		} else if (!(imm & ~0xffffffffULL) && codes->rilf != (it)-1) {
			code = codes->rilf;
			if (codes->neg_imm == 2)
				imm = ~imm;
			code |= (it)(imm & 0xffffffffLL);
		} else if (!(imm & ~0xffffffff00000000ULL) && codes->rihf != (it)-1) {
			code = codes->rihf;
			if (codes->neg_imm == 2)
				imm = ~imm;
			code |= (it)(((uint64_t)imm & 0xffffffff00000000LL) >> 32);
		} else {
			goto invl;
		}
		code |= (it)arg1[0] << 36;
		g(cgen_s390(ctx, code));
		return true;
	} else if (arg3[0] == ARG_ADDRESS_0) {
		b = 0;
		x = 0;
		disp = &arg3[1];
	} else if (arg3[0] == ARG_ADDRESS_1) {
		b = arg3[1];
		x = 0;
		disp = &arg3[2];
	} else if (arg3[0] == ARG_ADDRESS_2) {
		b = arg3[1];
		x = arg3[2];
		disp = &arg3[3];
	} else {
		goto invl;
	}

	imm = get_imm(disp);
	if (size != OP_SIZE_8) {
		if (imm >= 0 && imm < 0x1000 && codes->rx != (it)-1) {
			code = codes->rx;
			code |= (it)arg1[0] << 36;
			code |= (it)x << 32;
			code |= (it)b << 28;
			code |= (it)(imm & 0xfff) << 16;
		} else if (imm >= -0x80000 && imm < 0x80000) {
			code = codes->rxy;
			goto rxya;
		} else {
			goto invl;
		}
	} else {
		code = codes->rxg;
		if (imm >= -0x80000 && imm < 0x80000) {
rxya:
			code |= (it)arg1[0] << 36;
			code |= (it)x << 32;
			code |= (it)b << 28;
			code |= (it)(imm & 0xfff) << 16;
			code |= (it)(imm & 0xff000) >> 4;
		} else {
			goto invl;
		}

	}
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_rr_rx: invalid arguments %u, %02x, %02x, %02x", size, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_fp_mem(struct codegen_context *ctx, unsigned size, uint8_t *arg1, uint8_t *arg2, it e, it ey, it d, it dy)
{
	it code;
	uint8_t b, x;
	uint8_t *disp;
	int64_t imm;
	if (size != OP_SIZE_4 && size != OP_SIZE_8)
		goto invl;
	if (unlikely(!reg_is_fp(arg1[0])))
		goto invl;
	if (arg2[0] == ARG_ADDRESS_0) {
		b = 0;
		x = 0;
		disp = &arg2[1];
	} else if (arg2[0] == ARG_ADDRESS_1) {
		b = arg2[1];
		x = 0;
		disp = &arg2[2];
	} else if (arg2[0] == ARG_ADDRESS_2) {
		b = arg2[1];
		x = arg2[2];
		disp = &arg2[3];
	} else {
		goto invl;
	}
	imm = get_imm(disp);
	if (imm >= 0 && imm < 4096) {
		code = size == OP_SIZE_4 ? e : d;
	} else if (imm >= -0x80000 && imm < 0x80000) {
		code = size == OP_SIZE_4 ? ey : dy;
		code |= (it)(imm & 0xff000) >> 4;
	} else {
		goto invl;
	}
	code |= (it)(arg1[0] & 0xf) << 36;
	code |= (it)x << 32;
	code |= (it)b << 28;
	code |= (it)(imm & 0xfff) << 16;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_fp_mem: invalid arguments %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_fp_op(struct codegen_context *ctx, unsigned size, uint8_t *arg1, uint8_t *arg2, const struct fp_alu *fp_alu)
{
	it code;
	uint8_t b, x;
	uint8_t *disp;
	int64_t imm;
	if (size != OP_SIZE_4 && size != OP_SIZE_8 && size != OP_SIZE_16)
		goto invl;
	if (reg_is_fp(arg2[0])) {
		code = size == OP_SIZE_4 ? fp_alu->err : size == OP_SIZE_8 ? fp_alu->drr : fp_alu->xrr;
		code |= (it)(arg1[0] & 0xf) << 20;
		code |= (it)(arg2[0] & 0xf) << 16;
		g(cgen_s390(ctx, code));
		return true;
	} else if (arg2[0] == ARG_ADDRESS_0) {
		b = 0;
		x = 0;
		disp = &arg2[1];
	} else if (arg2[0] == ARG_ADDRESS_1) {
		b = arg2[1];
		x = 0;
		disp = &arg2[2];
	} else if (arg2[0] == ARG_ADDRESS_2) {
		b = arg2[1];
		x = arg2[2];
		disp = &arg2[3];
	} else {
		goto invl;
	}
	imm = get_imm(disp);
	if (unlikely(imm < 0) || unlikely(imm >= 4096))
		goto invl;
	if (unlikely(size == OP_SIZE_16))
		goto invl;
	code = size == OP_SIZE_4 ? fp_alu->erx : fp_alu->drx;
	code |= (it)(arg1[0] & 0xf) << 36;
	code |= (it)x << 32;
	code |= (it)b << 28;
	code |= (it)(imm & 0xfff) << 16;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_fp_op: invalid arguments %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_xi(struct codegen_context *ctx, uint8_t *arg1, uint8_t *arg2, it xi, it xiy)
{
	it code;
	uint8_t b;
	uint8_t *disp;
	int64_t val, imm;
	if (unlikely(arg1[0] == ARG_ADDRESS_0)) {
		b = 0;
		disp = &arg1[1];
	} else if (likely(arg1[0] == ARG_ADDRESS_1) && likely(arg2[0] == ARG_IMM)) {
		b = arg1[1];
		disp = &arg1[2];
	} else {
		goto invl;
	}

	imm = get_imm(disp);
	if (likely(arg2[0] == ARG_IMM)) {
		val = get_imm(&arg2[1]);
	} else {
		goto invl;
	}

	if (imm >= 0 && imm < 0x1000) {
		code = xi;
		code |= (it)(imm & 0xfff) << 16;
	} else if (imm >= -0x80000 && imm < 0x80000) {
		code = xiy;
		code |= (it)(imm & 0xfff) << 16;
		code |= (it)(imm & 0xff000) >> 4;
	} else {
		goto invl;
	}

	code |= (it)(val & 0xff) << 32;
	code |= (it)b << 28;

	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_xi: invalid arguments %02x, %02x", *arg1, *arg2);
	return false;
}

static bool attr_w cgen_lm_stm(struct codegen_context *ctx, unsigned size, uint8_t r_start, uint8_t r_end, uint8_t *arg1, it m, it my, it mg)
{
	it code;
	int64_t imm;
	if (unlikely(r_start >= 0x10) || unlikely(r_end >= 0x10) || unlikely(arg1[0] != ARG_ADDRESS_1) || unlikely(size < OP_SIZE_4) || unlikely(size > OP_SIZE_8))
		goto invl;
	imm = get_imm(&arg1[2]);
	if (size == OP_SIZE_4 && imm >= 0 && imm < 0x1000) {
		code = m;
		code |= (it)(imm & 0xfff) << 16;
	} else {
		if (size == OP_SIZE_4)
			code = my;
		else
			code = mg;
		code |= (it)(imm & 0xfff) << 16;
		code |= (it)(imm & 0xff000) >> 4;
	}
	code |= (it)r_start << 36;
	code |= (it)r_end << 32;
	code |= (it)arg1[1] << 28;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_lm_stm: invalid arguments %02x", *arg1);
	return false;
}

static bool attr_w cgen_s390_push_pop(struct codegen_context *ctx, unsigned size, bool push)
{
	uint8_t *arg1;
	arg1 = ctx->code_position;
	ctx->code_position = arg1 + arg_size(*arg1);
	if (!push)
		g(cgen_lm_stm(ctx, size, R_6, R_15, arg1, S390_LM, S390_LMY, S390_LMG));
	else
		g(cgen_lm_stm(ctx, size, R_6, R_15, arg1, S390_STM, S390_STMY, S390_STMG));
	return true;
}

static bool attr_w cgen_call_indirect(struct codegen_context *ctx)
{
	uint8_t reg = cget_one(ctx);
	it code = S390_BASR;
	code |= (it)R_14 << 36;
	code |= (it)reg << 32;
	g(cgen_s390(ctx, code));
	return true;
}

static bool attr_w cgen_branch_imm(struct codegen_context *ctx, uint8_t reg, int64_t imm)
{
	it code;
	code = S390_BRAS;
	code |= (it)reg << 36;
	code |= (OP_SIZE_NATIVE == OP_SIZE_4 ? (it)4 : (it)6) << 16;
	g(cgen_s390(ctx, code));
	if (OP_SIZE_NATIVE == OP_SIZE_4) {
		cgen_four(imm);
	} else {
		cgen_eight(imm);
	}
	code = OP_SIZE_NATIVE == OP_SIZE_4 ? S390_L : S390_LG;
	code |= (it)reg << 36;
	code |= (it)reg << 28;
	g(cgen_s390(ctx, code));
	return true;
}

static bool attr_w cgen_mov(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (arg1[0] < 0x10) {
		if (unlikely(size != OP_SIZE_NATIVE)) {
			switch (size) {
				case OP_SIZE_1:
					if (unlikely(!cpu_test_feature(CPU_FEATURE_extended_imm)))
						goto invl;
					g(cgen_rr_rx(ctx, OP_SIZE_NATIVE, arg1, arg1, arg2, &codes_load_8_unsigned));
					return true;
				case OP_SIZE_2:
					if (unlikely(!cpu_test_feature(CPU_FEATURE_extended_imm)))
						goto invl;
					g(cgen_rr_rx(ctx, OP_SIZE_NATIVE, arg1, arg1, arg2, &codes_load_16_unsigned));
					return true;
				case OP_SIZE_4:
					g(cgen_rr_rx(ctx, OP_SIZE_NATIVE, arg1, arg1, arg2, &codes_load_32_unsigned));
					return true;
				default:
					goto invl;
			}
		}
		if (!cpu_test_feature(CPU_FEATURE_extended_imm) && arg2[0] == ARG_IMM) {
			int64_t imm = get_imm(&arg2[1]);
			if (imm < -0x8000 || imm >= 0x8000) {
				g(cgen_branch_imm(ctx, arg1[0], imm));
				return true;
			}
		}
		g(cgen_rr_rx(ctx, size, arg1, arg1, arg2, &codes_load));
		return true;
	}
	if (arg1[0] < 0x20) {
		if (unlikely(arg2[0] < 0x20))
			goto invl;
		if (unlikely(size < OP_SIZE_4) || unlikely(size > OP_SIZE_8))
			goto invl;
		g(cgen_fp_mem(ctx, size, arg1, arg2, S390_LE, S390_LEY, S390_LD, S390_LDY));
		return true;
	}
	if (arg2[0] < 0x10) {
		g(cgen_rr_rx(ctx, size, arg2, arg2, arg1, size == OP_SIZE_1 ? &codes_store_8 : size == OP_SIZE_2 ? &codes_store_16 : &codes_store));
		return true;
	}
	if (arg2[0] < 0x20) {
		if (unlikely(size < OP_SIZE_4) || unlikely(size > OP_SIZE_8))
			goto invl;
		g(cgen_fp_mem(ctx, size, arg2, arg1, S390_STE, S390_STEY, S390_STD, S390_STDY));
		return true;
	}
	if (size == OP_SIZE_1 && arg1[0] == ARG_ADDRESS_1 && arg2[0] == ARG_IMM) {
		g(cgen_xi(ctx, arg1, arg2, S390_MVI, S390_MVIY));
		return true;
	}
invl:
	internal(file_line, "cgen_mov: invalid arguments %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_movsx(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1, *arg2;
	if (unlikely(size == OP_SIZE_NATIVE)) {
		g(cgen_mov(ctx, size));
		return true;
	}
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	switch (size) {
		case OP_SIZE_1:
			if (arg2[0] >= 0x10 ? !cpu_test_feature(CPU_FEATURE_long_displacement) : !cpu_test_feature(CPU_FEATURE_extended_imm))
				goto invl;
			g(cgen_rr_rx(ctx, OP_SIZE_NATIVE, arg1, arg1, arg2, &codes_load_8));
			return true;
		case OP_SIZE_2:
			if (arg2[0] < 0x10 && !cpu_test_feature(CPU_FEATURE_extended_imm))
				goto invl;
			g(cgen_rr_rx(ctx, OP_SIZE_NATIVE, arg1, arg1, arg2, &codes_load_16));
			return true;
		case OP_SIZE_4:
			g(cgen_rr_rx(ctx, OP_SIZE_NATIVE, arg1, arg1, arg2, &codes_load_32));
			return true;
		default:
			goto invl;
	}
invl:
	internal(file_line, "cgen_movsx: invalid arguments %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_cmp(struct codegen_context *ctx, unsigned size, unsigned writes_flags)
{
	uint8_t *arg1, *arg2;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (writes_flags == 1) {
		g(cgen_rr_rx(ctx, size, arg1, arg1, arg2, &codes_cmp));
		return true;
	} else if (writes_flags == 2) {
		if (size == OP_SIZE_1 && arg1[0] == ARG_ADDRESS_1 && arg2[0] == ARG_IMM) {
			g(cgen_xi(ctx, arg1, arg2, S390_CLI, S390_CLIY));
			return true;
		}
		g(cgen_rr_rx(ctx, size, arg1, arg1, arg2, &codes_cmp_log));
		return true;
	}
	internal(file_line, "cgen_cmp: invalid arguments %u, %02x, %02x, %u", size, *arg1, *arg2, writes_flags);
	return false;
}

static bool attr_w cgen_test(struct codegen_context *ctx, unsigned size)
{
	it code;
	uint8_t *arg1, *arg2;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (likely(arg1[0] < 0x10) && likely(arg2[0] == ARG_IMM)) {
		uint16_t m;
		int64_t imm = get_imm(&arg2[1]);
		if (!(imm & ~0xffffULL)) {
			code = S390_TMLL;
			m = (uint64_t)imm;
		} else if (!(imm & ~0xffff0000ULL)) {
			code = S390_TMLH;
			m = (uint64_t)imm >> 16;
		} else if (!(imm & ~0xffff00000000ULL)) {
			code = S390_TMHL;
			m = (uint64_t)imm >> 32;
		} else if (!(imm & ~0xffff000000000000ULL)) {
			code = S390_TMHH;
			m = (uint64_t)imm >> 48;
		} else {
			goto invl;
		}
		code |= (it)m << 16;
		code |= (it)arg1[0] << 36;
		g(cgen_s390(ctx, code));
		return true;
	}
	if (arg1[0] < 0x10 && arg2[0] == arg1[0]) {
		if (size == OP_SIZE_4) {
			code = S390_LTR;
			code |= (it)arg1[0] << 36;
			code |= (it)arg1[0] << 32;
		} else if (size == OP_SIZE_8) {
			code = S390_LTGR;
			code |= (it)arg1[0] << 20;
			code |= (it)arg1[0] << 16;
		} else {
			goto invl;
		}
		g(cgen_s390(ctx, code));
		return true;
	}
invl:
	internal(file_line, "cgen_test: invalid arguments %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_alu(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] >= 0x10))
		goto invl;
	if (writes_flags == 0) {
		if (unlikely(alu >= n_array_elements(codes_alu_no_flags)))
			goto invl;
		if (unlikely(codes_alu_no_flags[alu].rr == (it)-1) && unlikely(codes_alu_no_flags[alu].rrk == (it)-1))
			goto invl;
		g(cgen_rr_rx(ctx, size, arg1, arg2, arg3, &codes_alu_no_flags[alu]));
	} else if (writes_flags == 1) {
		if (unlikely(alu >= n_array_elements(codes_alu)))
			goto invl;
		if (unlikely(codes_alu[alu].rr == (it)-1) && unlikely(codes_alu[alu].rrk == (it)-1))
			goto invl;
		g(cgen_rr_rx(ctx, size, arg1, arg2, arg3, &codes_alu[alu]));
	} else if (writes_flags == 2) {
		if (unlikely(alu >= n_array_elements(codes_alu_log)))
			goto invl;
		if (unlikely(codes_alu_log[alu].rr == (it)-1) && unlikely(codes_alu_log[alu].rrk == (it)-1))
			goto invl;
		g(cgen_rr_rx(ctx, size, arg1, arg2, arg3, &codes_alu_log[alu]));
	} else {
		goto invl;
	}
	return true;
invl:
	/*debug("%s", da(ctx->fn,function)->function_name);*/
	internal(file_line, "cgen_alu: invalid arguments %u, %u, %02x, %02x, %02x", size, alu, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_alu1(struct codegen_context *ctx, unsigned size, unsigned alu, unsigned writes_flags)
{
	it code;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] != arg1[0]))
		goto invl;
	switch (alu) {
		case ALU1_NEG:
			if (unlikely(writes_flags != 1))
				goto invl;
			if (size == OP_SIZE_4) {
				code = S390_LCR;
				code |= (it)arg1[0] << 36;
				code |= (it)arg2[0] << 32;
			} else if (size == OP_SIZE_8) {
				code = S390_LCGR;
				code |= (it)arg1[0] << 20;
				code |= (it)arg2[0] << 16;
			} else {
				goto invl;
			}
			break;
		case ALU1_INC:
		case ALU1_DEC:
			if (unlikely(writes_flags != 1))
				goto invl;
			if (size == OP_SIZE_4) {
				code = S390_AHI;
			} else if (size == OP_SIZE_8) {
				code = S390_AGHI;
			} else {
				goto invl;
			}
			code |= (it)arg1[0] << 36;
			if (alu == ALU1_INC)
				code |= (it)0x0001 << 16;
			else
				code |= (it)0xffff << 16;
			break;
		case ALU1_BSWAP:
			if (size == OP_SIZE_4) {
				code = S390_LRVR;
			} else if (size == OP_SIZE_8) {
				code = S390_LRVRG;
			} else {
				goto invl;
			}
			code |= (it)arg1[0] << 20;
			code |= (it)arg2[0] << 16;
			break;
		case ALU1_POPCNT:
			if (size != OP_SIZE_8)
				goto invl;
			code = S390_POPCNT;
			code |= (it)arg1[0] << 20;
			code |= (it)arg2[0] << 16;
			break;
		default:
			goto invl;
	}
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_alu1: invalid arguments %u, %u, %02x, %02x", size, alu, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_lea3(struct codegen_context *ctx)
{
	it code;
	int64_t imm;
	uint8_t *arg1, *arg2, *arg3, *arg4;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] >= 0x10) || unlikely(arg3[0] >= 0x10) || arg4[0] != ARG_IMM)
		goto invl;
	imm = get_imm(&arg4[1]);
	if (imm >= 0 && imm < 0x1000) {
		code = S390_LA;
	} else {
		code = S390_LAY;
		code |= (it)(imm & 0xff000) >> 4;
	}
	code |= (it)arg1[0] << 36;
	code |= (it)arg2[0] << 32;
	code |= (it)arg3[0] << 28;
	code |= (it)(imm & 0xfff) << 16;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_lea3: invalid arguments %02x, %02x, %02x, %02x", *arg1, *arg2, *arg3, *arg4);
	return false;
}

static bool attr_w cgen_rot(struct codegen_context *ctx, unsigned size, unsigned alu)
{
	it code;
	unsigned sz;
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] >= 0x10))
		goto invl;
	if (arg3[0] >= 0x10 && unlikely(arg3[0] != ARG_IMM))
		goto invl;

	if (size == OP_SIZE_4 && arg1[0] == arg2[0]) {
		code = rot32[alu];
	} else if (size == OP_SIZE_4) {
		code = rot32k[alu];
	} else if (size == OP_SIZE_8) {
		code = rot64[alu];
	} else {
		goto invl;
	}
	sz = code >> 46;
	if (sz == 1 || sz == 2) {
		code |= (it)arg1[0] << 36;
	} else if (sz == 3) {
		code |= (it)arg1[0] << 36;
		code |= (it)arg2[0] << 32;
	} else {
		goto invl;
	}
	if (arg3[0] == ARG_IMM)
		code |= (it)(get_imm(&arg3[1]) & (size == OP_SIZE_4 ? 0x1f : 0x3f)) << 16;
	else
		code |= (it)arg3[0] << 28;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_rot: invalid arguments %u, %u, %02x, %02x, %02x", size, alu, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_mul_l(struct codegen_context *ctx, unsigned size)
{
	it code;
	uint8_t *arg1, *arg2, *arg3, *arg4;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	ctx->code_position = arg4 + arg_size(*arg4);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] >= 0x10) || unlikely(arg3[0] >= 0x10) || unlikely(arg4[0] >= 0x10))
		goto invl;
	if (unlikely(arg2[0] & 1) || unlikely(arg1[0] != arg2[0] + 1) || unlikely(arg3[0] != arg1[0]))
		goto invl;
	if (size == OP_SIZE_4) {
		code = S390_MR;
		code |= (it)arg2[0] << 36;
		code |= (it)arg4[0] << 32;
	} else {
		code = S390_MGRK;
		code |= (it)arg2[0] << 20;
		code |= (it)arg3[0] << 16;
		code |= (it)arg4[0] << 28;
	}
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_mul_l: invalid arguments %02x, %02x, %02x, %02x", *arg1, *arg2, *arg3, *arg4);
	return false;
}

static bool attr_w cgen_div_l(struct codegen_context *ctx, unsigned size, bool sgn)
{
	it code;
	uint8_t *arg1, *arg2, *arg3, *arg4, *arg5;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	arg4 = arg3 + arg_size(*arg3);
	arg5 = arg4 + arg_size(*arg4);
	ctx->code_position = arg5 + arg_size(*arg5);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] >= 0x10) || unlikely(arg3[0] >= 0x10) || unlikely(arg4[0] >= 0x10) || unlikely(arg5[0] >= 0x10))
		goto invl;
	if (unlikely(arg1[0] & 1) || unlikely(arg2[0] != arg1[0] + 1))
		goto invl;
	if (unlikely(arg3[0] != arg1[0]) || unlikely(arg4[0] != arg3[0] + 1))
		goto invl;
	if (!sgn) {
		code = size == OP_SIZE_4 ? S390_DLR : S390_DLGR;
	} else {
		code = size == OP_SIZE_4 ? S390_DR : S390_DSGR;
	}
	if (code == S390_DR) {
		code |= (it)arg1[0] << 36;
		code |= (it)arg5[0] << 32;
	} else {
		code |= (it)arg1[0] << 20;
		code |= (it)arg5[0] << 16;
	}
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_div_l: invalid arguments %02x, %02x, %02x, %02x, %02x", *arg1, *arg2, *arg3, *arg4, *arg4);
	return false;
}

static bool attr_w cgen_cmov(struct codegen_context *ctx, unsigned size, unsigned cond, bool logical)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != arg2[0]) || arg1[0] >= 0x10)
		goto invl;

	if (arg3[0] < 0x10) {
		it code;
		code = size == OP_SIZE_4 ? S390_LOCR : S390_LOCGR;
		code |= (it)get_jmp_cond(cond, logical) << 28;
		code |= (it)arg1[0] << 20;
		code |= (it)arg3[0] << 16;
		g(cgen_s390(ctx, code));
		return true;
	} else if (arg3[0] == ARG_ADDRESS_1) {
		it code;
		int64_t imm;
		code = size == OP_SIZE_4 ? S390_LOC : S390_LOCG;
		code |= (it)get_jmp_cond(cond, logical) << 32;
		code |= (it)arg1[0] << 36;
		code |= (it)arg3[1] << 28;
		imm = get_imm(&arg3[2]);
		if (imm < -0x80000 || imm >= 0x80000)
			goto invl;
		code |= (it)(imm & 0xfff) << 16;
		code |= (it)(imm & 0xff000) >> 4;
		g(cgen_s390(ctx, code));
		return true;
	}

invl:
	internal(file_line, "cgen_cmov: invalid arguments %02x, %02x, %02x", *arg1, *arg2, *arg3);
}

static bool attr_w cgen_ldp_stp(struct codegen_context *ctx, unsigned size, bool st)
{
	uint8_t *arg1, *arg2, *arg3;
	if (!st) {
		arg2 = ctx->code_position;
		arg3 = arg2 + arg_size(*arg2);
		arg1 = arg3 + arg_size(*arg3);
		ctx->code_position = arg1 + arg_size(*arg1);
	} else {
		arg1 = ctx->code_position;
		arg2 = arg1 + arg_size(*arg1);
		arg3 = arg2 + arg_size(*arg2);
		ctx->code_position = arg3 + arg_size(*arg3);
	}
	if (unlikely(arg2[0] >= 0x10) || unlikely(arg3[0] >= 0x10))
		goto invl;
	if (unlikely(arg2[0] != arg3[0] + 1))
		goto invl;
	if (!st)
		g(cgen_lm_stm(ctx, size, arg3[0], arg2[0], arg1, S390_LM, S390_LMY, S390_LMG));
	else
		g(cgen_lm_stm(ctx, size, arg3[0], arg2[0], arg1, S390_STM, S390_STMY, S390_STMG));
	return true;
invl:
	internal(file_line, "cgen_ldp_stp: invalid arguments %u, %02x, %02x, %02x", size, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_ic(struct codegen_context *ctx)
{
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] != arg1[0]))
		goto invl;
	g(cgen_rr_rx(ctx, OP_SIZE_4, arg1, arg2, arg3, &codes_ic));
	return true;
invl:
	internal(file_line, "cgen_ic: invalid arguments %02x, %02x, %02x", *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_mov_mask(struct codegen_context *ctx)
{
	it code;
	int64_t imm;
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] >= 0x10) || unlikely(arg2[0] != arg1[0]) || unlikely(arg3[0] != ARG_IMM))
		goto invl;
	imm = get_imm(&arg3[1]);
	code = S390_IIHF;
	code |= (it)arg1[1] << 36;
	code |= (it)(imm & 0xffffffffLL);
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_mov_mask: invalid arguments %02x, %02x, %02x", *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_memcpy(struct codegen_context *ctx)
{
	it code;
	int64_t disp_dest, disp_src, len;
	uint8_t *arg1, *arg2, *arg3;
	arg1 = ctx->code_position;
	arg2 = arg1 + arg_size(*arg1);
	arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(arg1[0] != ARG_ADDRESS_1) || unlikely(arg2[0] != ARG_ADDRESS_1) || unlikely(arg3[0] != ARG_IMM))
		goto invl;
	disp_dest = get_imm(&arg1[2]);
	disp_src = get_imm(&arg2[2]);
	len = get_imm(&arg3[1]);
	code = S390_MVC;
	code |= (it)((len - 1) & 0xff) << 32;
	code |= (it)arg1[1] << 28;
	code |= (it)(disp_dest & 0xfff) << 16;
	code |= (it)arg2[1] << 12;
	code |= (it)(disp_src & 0xfff) << 0;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_memcpy: invalid arguments %02x, %02x, %02x", *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_fp_cmp(struct codegen_context *ctx, unsigned size)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (unlikely(!reg_is_fp(arg1[0])))
		goto invl;
	g(cgen_fp_op(ctx, size, arg1, arg2, &fp_cmp));
	return true;
invl:
	internal(file_line, "cgen_fp_cmp: invalid arguments %u, %02x, %02x", size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_fp_alu(struct codegen_context *ctx, unsigned size, unsigned aux)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	uint8_t *arg3 = arg2 + arg_size(*arg2);
	ctx->code_position = arg3 + arg_size(*arg3);
	if (unlikely(!reg_is_fp(arg1[0])) || unlikely(arg1[0] != arg2[0]))
		goto invl;
	g(cgen_fp_op(ctx, size, arg1, arg3, &fp_alus[aux]));
	return true;
invl:
	internal(file_line, "cgen_fp_alu: invalid arguments %u, %u, %02x, %02x, %02x", size, aux, *arg1, *arg2, *arg3);
	return false;
}

static bool attr_w cgen_fp_alu1(struct codegen_context *ctx, unsigned size, unsigned aux)
{
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (unlikely(!reg_is_fp(arg1[0])))
		goto invl;
	g(cgen_fp_op(ctx, size, arg1, arg2, &fp_alu1s[aux]));
	return true;
invl:
	internal(file_line, "cgen_fp_alu1: invalid arguments %u, %u, %02x, %02x", size, aux, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_fp_to_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	it code;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (unlikely(arg1[0] >= 0x10) || unlikely(!reg_is_fp(arg2[0])))
		goto invl;
	switch (fp_op_size) {
		case OP_SIZE_4:
			code = int_op_size == OP_SIZE_4 ? S390_CFEBR : S390_CGEBR;
			break;
		case OP_SIZE_8:
			code = int_op_size == OP_SIZE_4 ? S390_CFDBR : S390_CGDBR;
			break;
		case OP_SIZE_16:
			code = int_op_size == OP_SIZE_4 ? S390_CFXBR : S390_CGXBR;
			break;
		default:
			goto invl;
	}
	code |= (it)5 << 28;
	code |= (it)arg1[0] << 20;
	code |= (it)(arg2[0] & 0xf) << 16;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_fp_to_int: invalid arguments %u, %u, %02x, %02x", int_op_size, fp_op_size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_fp_from_int(struct codegen_context *ctx, unsigned int_op_size, unsigned fp_op_size)
{
	it code;
	uint8_t *arg1 = ctx->code_position;
	uint8_t *arg2 = arg1 + arg_size(*arg1);
	ctx->code_position = arg2 + arg_size(*arg2);
	if (unlikely(!reg_is_fp(arg1[0])) || unlikely(arg2[0] >= 0x10))
		goto invl;
	switch (fp_op_size) {
		case OP_SIZE_4:
			code = int_op_size == OP_SIZE_4 ? S390_CEFBR : S390_CEGBR;
			break;
		case OP_SIZE_8:
			code = int_op_size == OP_SIZE_4 ? S390_CDFBR : S390_CDGBR;
			break;
		case OP_SIZE_16:
			code = int_op_size == OP_SIZE_4 ? S390_CXFBR : S390_CXGBR;
			break;
		default:
			goto invl;
	}
	code |= (it)(arg1[0] & 0xf) << 20;
	code |= (it)arg2[0] << 16;
	g(cgen_s390(ctx, code));
	return true;
invl:
	internal(file_line, "cgen_fp_from_int: invalid arguments %u, %u, %02x, %02x", int_op_size, fp_op_size, *arg1, *arg2);
	return false;
}

static bool attr_w cgen_jmp_cond(struct codegen_context *ctx, bool lng, unsigned aux, bool logical)
{
	it code;
	if (!lng) {
		g(add_relocation(ctx, JMP_SHORTEST, 0, NULL));
		code = S390_BRC;
	} else if (USE_BRCL) {
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		code = S390_BRCL;
	} else {
		g(add_relocation(ctx, JMP_SHORT, 0, NULL));
		code = S390_BRAS;
		code |= (it)R_OFFSET_IMM << 36;
		code |= (it)4 << 16;
		g(cgen_s390(ctx, code));
		cgen_four(0);
#if defined(ARCH_S390_32)
		code = S390_L;
#else
		code = S390_LGF;
#endif
		code |= (it)R_CONST_IMM << 36;
		code |= (it)R_OFFSET_IMM << 28;
		g(cgen_s390(ctx, code));
		code = S390_LA;
		code |= (it)R_OFFSET_IMM << 36;
		code |= (it)R_OFFSET_IMM << 32;
		code |= (it)R_CONST_IMM << 28;
		g(cgen_s390(ctx, code));
		code = S390_BCR;
		code |= (it)R_OFFSET_IMM << 32;
		code |= (it)get_jmp_cond(aux, logical) << 36;
		g(cgen_s390(ctx, code));
		return true;
	}
	code |= (it)get_jmp_cond(aux, logical) << 36;
	g(cgen_s390(ctx, code));
	return true;
}

static bool attr_w cgen_jmp_indirect(struct codegen_context *ctx)
{
	uint8_t reg = cget_one(ctx);
	it code = S390_BCR;
	code |= (it)(S390_BRC_OVF | S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_EQ) << 36;
	code |= (it)reg << 32;
	g(cgen_s390(ctx, code));
	return true;
}

static bool attr_w resolve_relocation(struct codegen_context *ctx, struct relocation *reloc)
{
	int64_t offs = ((int64_t)ctx->label_to_pos[reloc->label_id] - (int64_t)(reloc->position)) / 2;
	switch (reloc->length) {
		case JMP_SHORTEST: {
			int16_t i16;
			if (unlikely(offs < -0x8000) || unlikely(offs >= 0x8000))
				return false;
			i16 = offs;
			memcpy(ctx->mcode + reloc->position + 2, &i16, 2);
			return true;
		}
		case JMP_SHORT: {
			int32_t i32;
			if (USE_BRCL) {
				if (unlikely(offs < -0x80000000LL) || unlikely(offs >= 0x80000000LL))
					return false;
				i32 = offs;
				memcpy(ctx->mcode + reloc->position + 2, &i32, 4);
				return true;
			} else {
				offs *= 2;
				offs -= 4;
				if (unlikely(offs < -0x80000000LL) || unlikely(offs >= 0x80000000LL))
					return false;
				i32 = offs;
				memcpy(ctx->mcode + reloc->position + 4, &i32, 4);
				return true;
			}
		}
		default: {
			internal(file_line, "resolve_relocation: invalid relocation length %u", reloc->length);
			return false;
		}
	}
}

static bool attr_w cgen_insn(struct codegen_context *ctx, uint32_t insn)
{
	/*debug("insn: %08x", insn);*/
	switch (insn_opcode(insn)) {
		case INSN_ENTRY:
			g(cgen_entry(ctx));
			return true;
		case INSN_LABEL:
			g(cgen_label(ctx));
			return true;
		case INSN_RET:
			g(cgen_s390(ctx, S390_BCR | ((it)(S390_BRC_OVF | S390_BRC_GREATER | S390_BRC_LESS | S390_BRC_EQ) << 36) | ((it)R_14 << 32)));
			return true;
		case INSN_S390_PUSH:
			g(cgen_s390_push_pop(ctx, insn_op_size(insn), true));
			return true;
		case INSN_S390_POP:
			g(cgen_s390_push_pop(ctx, insn_op_size(insn), false));
			return true;
		case INSN_CALL_INDIRECT:
			g(cgen_call_indirect(ctx));
			return true;
		case INSN_MOV:
			g(cgen_mov(ctx, insn_op_size(insn)));
			return true;
		case INSN_MOVSX:
			g(cgen_movsx(ctx, insn_op_size(insn)));
			return true;
		case INSN_CMP:
			g(cgen_cmp(ctx, insn_op_size(insn), insn_writes_flags(insn)));
			return true;
		case INSN_TEST:
			if (unlikely(!insn_writes_flags(insn)))
				goto invalid_insn;
			g(cgen_test(ctx, insn_op_size(insn)));
			return true;
		case INSN_ALU:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU_PARTIAL:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) >= OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU1:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_ALU1_PARTIAL:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) >= OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_alu1(ctx, insn_op_size(insn), insn_aux(insn), insn_writes_flags(insn)));
			return true;
		case INSN_LEA3:
			if (unlikely(insn_op_size(insn) != OP_SIZE_ADDRESS))
				goto invalid_insn;
			if (unlikely(insn_aux(insn) != 0))
				goto invalid_insn;
			g(cgen_lea3(ctx));
			return true;
		case INSN_ROT:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_ROT_PARTIAL:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) >= OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_rot(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_MUL_L:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) > OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_mul_l(ctx, insn_op_size(insn)));
			return true;
		case INSN_DIV_L:
			g(cgen_div_l(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_CMOV:
		case INSN_CMOV_XCC:
			if (unlikely(!cpu_test_feature(CPU_FEATURE_misc_45)))
				goto invalid_insn;
			g(cgen_cmov(ctx, insn_op_size(insn), insn_aux(insn), insn_opcode(insn) == INSN_CMOV_XCC));
			return true;
		case INSN_STP:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) > OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_ldp_stp(ctx, insn_op_size(insn), true));
			return true;
		case INSN_LDP:
			if (unlikely(insn_op_size(insn) <= OP_SIZE_2) || unlikely(insn_op_size(insn) > OP_SIZE_NATIVE))
				goto invalid_insn;
			g(cgen_ldp_stp(ctx, insn_op_size(insn), false));
			return true;
		case INSN_MOV_MASK:
			if (unlikely(insn_op_size(insn) != OP_SIZE_NATIVE))
				goto invalid_insn;
			if (insn_aux(insn) == MOV_MASK_0_8) {
				g(cgen_ic(ctx));
			} else if (insn_aux(insn) == MOV_MASK_32_64) {
				g(cgen_mov_mask(ctx));
			} else {
				goto invalid_insn;
			}
			return true;
		case INSN_MEMCPY:
			g(cgen_memcpy(ctx));
			return true;
		case INSN_FP_CMP:
			g(cgen_fp_cmp(ctx, insn_op_size(insn)));
			return true;
		case INSN_FP_ALU:
			g(cgen_fp_alu(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_ALU1:
			g(cgen_fp_alu1(ctx, insn_op_size(insn), insn_aux(insn)));
			return true;
		case INSN_FP_TO_INT32:
			g(cgen_fp_to_int(ctx, OP_SIZE_4, insn_op_size(insn)));
			return true;
		case INSN_FP_TO_INT64:
			g(cgen_fp_to_int(ctx, OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_FP_FROM_INT32:
			g(cgen_fp_from_int(ctx, OP_SIZE_4, insn_op_size(insn)));
			return true;
		case INSN_FP_FROM_INT64:
			g(cgen_fp_from_int(ctx, OP_SIZE_8, insn_op_size(insn)));
			return true;
		case INSN_JMP:
			g(cgen_jmp_cond(ctx, insn_jump_size(insn) == JMP_SHORT, COND_ALWAYS, false));
			return true;
		case INSN_JMP_COND:
			g(cgen_jmp_cond(ctx, insn_jump_size(insn) == JMP_SHORT, insn_aux(insn), false));
			return true;
		case INSN_JMP_COND_LOGICAL:
			g(cgen_jmp_cond(ctx, insn_jump_size(insn) == JMP_SHORT, insn_aux(insn), true));
			return true;
		case INSN_JMP_INDIRECT:
			g(cgen_jmp_indirect(ctx));
			return true;
		default:
		invalid_insn:
			internal(file_line, "cgen_insn: invalid insn %08x", insn);
			return false;
	}
}
