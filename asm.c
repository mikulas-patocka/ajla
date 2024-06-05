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

#include "ajla.h"

#include "str.h"
#include "os_util.h"
#include "arithm-b.h"
#include "arithm-i.h"
#include "arithm-r.h"

#include "asm.h"

#ifdef DEBUG_CRASH_HANDLER
void *u_data_trap_lookup(void *ptr);
void *c_data_trap_lookup(void *ptr);
static void dump_registers(int sig, ucontext_t *uc)
{
	int i;
#if defined(ARCH_IA64)
	debug("%s at %lx", sig == SIGSEGV ? "sigsegv" : sig == SIGBUS ? "sigbus" : "sigill", uc->uc_mcontext.sc_ip);
	for (i = 0; i < 32; i += 2) {
		debug("gr_%02x = %016lx	gr_%02x = %016lx", i, uc->uc_mcontext.sc_gr[i], i + 1, uc->uc_mcontext.sc_gr[i + 1]);
	}
	/*for (i = 0; i < 32; i += 2) {
		debug("gr_%02x = %016lx	gr_%02x = %016lx", 32 + i, ptr[i - 16], 32 + i + 1, ptr[i + 1 - 16]);
	}*/
	for (i = 0; i < 8; i += 2) {
		debug("br_%02x = %016lx	br_%02x = %016lx", i, uc->uc_mcontext.sc_br[i], i + 1, uc->uc_mcontext.sc_br[i + 1]);
	}
#endif
#if defined(ARCH_MIPS)
	debug("%s at %llx", sig == SIGSEGV ? "sigsegv" : sig == SIGBUS ? "sigbus" : "sigill", uc->uc_mcontext.pc);
	for (i = 0; i < 32; i++)
		debug("gpr_%d = %llx", i, uc->uc_mcontext.gregs[i]);
	call(data_trap_lookup)(num_to_ptr(uc->uc_mcontext.pc));
#endif
#if defined(ARCH_POWER)
	debug("%s at %lx", sig == SIGSEGV ? "sigsegv" : sig == SIGBUS ? "sigbus" : "sigill", uc->uc_mcontext.regs->nip);
	for (i = 0; i < 32; i++)
		debug("gpr_%d = %lx", i, uc->uc_mcontext.regs->gpr[i]);
#endif
#if defined(__SH4__)
	debug("%s at %x", sig == SIGSEGV ? "sigsegv" : sig == SIGBUS ? "sigbus" : "sigill", uc->uc_mcontext.pc);
	for (i = 0; i < 16; i++)
		debug("gpr_%d = %x", i, uc->uc_mcontext.gregs[i]);
	debug("pr = %x", uc->uc_mcontext.pr);
	debug("sr = %x", uc->uc_mcontext.sr);
	debug("gbr = %x", uc->uc_mcontext.gbr);
	debug("mach = %x", uc->uc_mcontext.mach);
	debug("macl = %x", uc->uc_mcontext.macl);
#endif
}
static void crash(int sig, siginfo_t attr_unused *siginfo, void *ucontext)
{
	dump_registers(sig, ucontext);
	_exit(127);
}
#endif

static const char * const cpu_feature_names[] = {
#define ASM_INC_NAMES
#include "asm.inc"
#undef ASM_INC_NAMES
	NULL
};

cpu_feature_mask_t cpu_feature_flags = 0;
static bool detection_failed;



#ifdef ARCH_ALPHA

static uint32_t amask = 0;
static void alpha_read_amask(void)
{
	char *c;
	size_t cs;
	uint64_t (*fn)(void);
	uint64_t res;
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "ffff1f20200ce0470180fa6b");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	res = fn();
	os_code_unmap(fn, cs);
	amask = ~res;
}

#endif



#ifdef ARCH_ARM

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

static uint32_t elf_hwcap;
static unsigned arm_arch;

static char *proc_get_field(const char *data, const char *field)
{
again:
	if (!strncmp(data, field, strlen(field))) {
		const char *colon, *newline;
		colon = strchr(data, ':');
		newline = strchr(data, '\n');
		if (!newline)
			newline = strchr(data, 0);
		if (!colon || colon > newline)
			return NULL;
		colon++;
		while (*colon == ' ' || *colon == '\t')
			colon++;
		return str_dup(colon, newline - colon, NULL);
	}
	data = strchr(data, '\n');
	if (!data)
		return NULL;
	data++;
	goto again;
}

static void arm_read_caps(void)
{
	ajla_error_t sink;
	char *data;
	char *arch;
	size_t i, l;
	unsigned long c = 0;
	elf_hwcap = c;
	arm_arch = ARM_VERSION;
#if defined(HAVE_GETAUXVAL) && defined(AT_PLATFORM) && !defined(UNUSUAL)
	c = getauxval(AT_PLATFORM);
	if (c) {
		const char *p = (const char *)c;
		if (!strcmp(p, "aarch64")) {
			arm_arch = 8;
			goto got_arch;
		}
		if (p[0] != 'v')
			goto no_aux_platform;
		if (p[1] < '1' || p[1] > '9')
			goto no_aux_platform;
		arm_arch = atoi(&p[1]);
		goto got_arch;
	}
	no_aux_platform:
#endif
	if (!os_read_file("/proc/cpuinfo", &data, &l, &sink))
		array_init(char, &data, &l);
	array_add(char, &data, &l, 0);
	arch = proc_get_field(data, "CPU architecture");
	if (arch) {
		int a = atoi(arch);
		if (a == 7) {
			char *proc = proc_get_field(data, "Processor");
			if (!proc) proc = proc_get_field(data, "model name");
			if (proc) {
				if (strstr(proc, "(v6l)"))
					a = 6;
				mem_free(proc);
			}
		}
		mem_free(arch);
		if (a > 0) {
			arm_arch = a;
			goto got_arch_free;
		}
	}
#ifdef ARM_VERSION_UNKNOWN
	detection_failed = true;
#endif
got_arch_free:
	mem_free(data);
	goto got_arch;	/* avoid warning */
got_arch:
#if defined(HAVE_GETAUXVAL) && defined(AT_HWCAP) && !defined(UNUSUAL)
	c = getauxval(AT_HWCAP);
	if (c) {
		elf_hwcap = c;
		goto got_hwcap;
	}
#endif
	if (!os_read_file("/proc/self/auxv", &data, &l, &sink))
		array_init(char, &data, &l);
	for (i = 0; i + sizeof(unsigned long) * 2 > i && i + sizeof(unsigned long) * 2 <= l; i += sizeof(unsigned long) * 2) {
		unsigned long tag = *(unsigned long *)(data + i);
		unsigned long value = *(unsigned long *)(data + i + sizeof(unsigned long));
		if (tag == 16) {
			elf_hwcap = value;
			goto got_hwcap_free;
		}
	}

	detection_failed = true;
got_hwcap_free:
	mem_free(data);
	goto got_hwcap;	/* avoid warning */
got_hwcap:
	;
	/*debug("arm arch %u, caps %x", arm_arch, elf_hwcap);*/
}

#endif


#ifdef ARCH_IA64

static uint64_t cpuid_4 = 0;
static void ia64_read_cpuid(void)
{
	void * volatile desc[2];
	char *c;
	size_t cs;
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "0a4000401704000000020000000004001d000000010000000002008008008400");
	desc[0] = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	desc[1] = NULL;
	cpuid_4 = ((uint64_t (*)(uint64_t))desc)(4);
	os_code_unmap(desc[0], cs);
}

#endif


#ifdef ARCH_LOONGARCH64

static uint32_t cpucfg_1 = 0;
static void loongarch_read_cpucfg(void)
{
	char *c;
	size_t cs;
	uint64_t (*fn)(uint64_t);
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "846c00002000004c");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	cpucfg_1 = fn(1);
	os_code_unmap(fn, cs);
}

#endif



#ifdef ARCH_PARISC32

#include <unistd.h>
static bool parisc_detect_20(void)
{
#if defined(__hpux) && defined(_SC_KERNEL_BITS)
	return sysconf(_SC_KERNEL_BITS) == 64;
#else
	os_utsname_t un;
	os_get_uname(&un);
	return !strcasecmp(un.machine, "parisc64");
#endif
}

#endif



#ifdef ARCH_POWER

static void sigill(int attr_unused sig, siginfo_t attr_unused *siginfo, void *ucontext)
{
	ucontext_t *uc = ucontext;
	uc->uc_mcontext.regs->nip += 4;
	uc->uc_mcontext.regs->gpr[3] = 0;
}

static bool trap_insn(const char *hex)
{
	char *c;
	size_t cs;
	size_t attr_unused i;
	int (*fn)(void);
	int ret;
	if (unlikely(!OS_SUPPORTS_TRAPS)) {
		detection_failed = true;
		return false;
	}
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "38600001");
	str_add_hex(&c, &cs, hex);
	str_add_hex(&c, &cs, "4e800020");
#if defined(C_LITTLE_ENDIAN)
	for (i = 0; i < cs; i += 4) {
		char t;
		t = c[i]; c[i] = c[i + 3]; c[i + 3] = t;
		t = c[i + 1]; c[i + 1] = c[i + 2]; c[i + 2] = t;
	}
#endif
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
#ifdef _CALL_AIXDESC
	{
		volatile uintptr_t desc[3];
		desc[0] = ptr_to_num(fn);
		desc[1] = 0;
		desc[2] = 0;
		ret = ((int (*)(void))desc)();
	}
#else
	ret = fn();
#endif
	os_code_unmap(fn, cs);
	/*debug("trap: %d", ret);*/
	return ret;
}

#endif



#ifdef ARCH_RISCV64

static void sigill(int attr_unused sig, siginfo_t attr_unused *siginfo, void *ucontext)
{
	ucontext_t *uc = ucontext;
	uc->uc_mcontext.__gregs[REG_PC] += 4;
	uc->uc_mcontext.__gregs[REG_A0] = 0;
}

static bool trap_insn(const char *hex)
{
	char *c;
	size_t cs;
	int (*fn)(void);
	int ret;
	if (unlikely(!OS_SUPPORTS_TRAPS)) {
		detection_failed = true;
		return false;
	}
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "0545");
	str_add_hex(&c, &cs, hex);
	str_add_hex(&c, &cs, "8280");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	ret = fn();
	os_code_unmap(fn, cs);
	/*debug("trap: %d", ret);*/
	return ret;
}

#endif



#ifdef ARCH_S390

static uint64_t s390_facilities[4];

static void s390_sigill(int attr_unused sig, siginfo_t attr_unused *siginfo, void *ucontext)
{
	ucontext_t *uc = ucontext;
	uc->uc_mcontext.psw.addr += 4;
	detection_failed = true;
}

static void s390_stfle(void)
{
	char *c;
	size_t cs;
	void (*fn)(uint64_t *);
	memset(&s390_facilities, 0, sizeof s390_facilities);
	if (unlikely(!OS_SUPPORTS_TRAPS)) {
		detection_failed = true;
		return;
	}
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "a7090003b2b0200007fe");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	os_signal_trap(SIGILL, s390_sigill);
	fn(s390_facilities);
	os_signal_restore(SIGILL);
	os_code_unmap(fn, cs);
#if 0
	debug("facilities0: %016llx", (unsigned long long)s390_facilities[0]);
	debug("facilities1: %016llx", (unsigned long long)s390_facilities[1]);
	debug("facilities2: %016llx", (unsigned long long)s390_facilities[2]);
	debug("facilities3: %016llx", (unsigned long long)s390_facilities[3]);
#endif
}

static bool test_facility(unsigned f)
{
	return (s390_facilities[f >> 6] >> (~f & 63)) & 1;
}

#endif



#ifdef ARCH_SPARC32

static bool sparc_detect_9(void)
{
	os_utsname_t un;
	os_get_uname(&un);
	return !strcasecmp(un.machine, "sparc64");
}

#endif



#ifdef ARCH_X86

#if !defined(ARCH_X86_32) || defined(__i686__) || defined(__athlon__) || defined(__SSE__)
#define test_eflags_bits()	do { } while (0)
#define eflags_bits		((1U << 18) | (1U << 21))
#else
static uint32_t eflags_bits = 0;
static void test_eflags_bits(void)
{
	char *c;
	size_t cs;
	uint32_t (*fn)(void);
	sig_state_t set;
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "b8000024009c330424509d9c583304249dc3");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	os_block_signals(&set);
	eflags_bits = fn();
	os_unblock_signals(&set);
	os_code_unmap(fn, cs);
}
#endif

static uint32_t cpuid_0[4];
static uint32_t cpuid_1[4];
static uint32_t cpuid_7[4];
static uint32_t cpuid_8_0[4];
static uint32_t cpuid_8_1[4];

static void do_cpuid(void)
{
	char *c;
	size_t cs;
	void (*cpuid)(uint32_t level, uint32_t sublevel, uint32_t *result);

	memset(cpuid_0, 0, sizeof cpuid_0);
	memset(cpuid_1, 0, sizeof cpuid_1);
	memset(cpuid_7, 0, sizeof cpuid_7);
	memset(cpuid_8_0, 0, sizeof cpuid_8_0);
	memset(cpuid_8_0, 1, sizeof cpuid_8_1);
	if (unlikely(!(eflags_bits & (1U << 21))))
		return;

	str_init(&c, &cs);
#if defined(ARCH_X86_32)
	str_add_hex(&c, &cs, "53568b44240c8b4c24100fa28b7424148906895e04894e0889560c5e5bc3");
#elif defined(ARCH_X86_64) && defined(ARCH_X86_WIN_ABI)
	str_add_hex(&c, &cs, "5389c889d10fa241890041895804418948084189500c5bc3");
#elif defined(ARCH_X86_64)
	str_add_hex(&c, &cs, "5389f889f14889d60fa28906895e04894e0889560c5bc3");
#elif defined(ARCH_X86_X32)
	str_add_hex(&c, &cs, "5389f889f189d60fa28906895e04894e0889560c5bc3");
#else
	unknown arch
#endif
	cpuid = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);

	cpuid(0, 0, cpuid_0);
	if (likely(cpuid_0[0] >= 1))
		cpuid(1, 0, cpuid_1);
	if (likely(cpuid_0[0] >= 7))
		cpuid(7, 0, cpuid_7);
	cpuid(0x80000000, 0, cpuid_8_0);
	if (likely((cpuid_8_0[0] & 0xffff0000) == 0x80000000)) {
		if (likely(cpuid_8_0[0] >= 0x80000001))
			cpuid(0x80000001, 0, cpuid_8_1);
	}

	os_code_unmap(cpuid, cs);
}

static bool test_fxsave(void)
{
#if defined(ARCH_X86_32)
	bool supported;
	unsigned char space[1024 + 15] = "";	/* avoid warning */
	unsigned char *mem = space + (-ptr_to_num(space) & 15);

	char *c;
	size_t cs;
	void (*fn)(unsigned char *ptr);

	mem[160] = 0;
	mem[160 + 512] = 0;

	str_init(&c, &cs);
	str_add_hex(&c, &cs, "8b4424040fae00fe80a00000000fae080fae8000020000c3");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	fn(mem);
	os_code_unmap(fn, cs);
	supported = mem[160] == mem[160 + 512];
	return supported;
#else
	return true;
#endif
}

static bool test_xcr0(unsigned mask)
{
	char *c;
	size_t cs;
	uint32_t (*fn)(void);
	uint32_t res;
	str_init(&c, &cs);
	str_add_hex(&c, &cs, "31c90f01d0c3");
	fn = os_code_map(cast_ptr(uint8_t *, c), cs, NULL);
	res = fn();
	os_code_unmap(fn, cs);
	return (res & mask) == mask;
}

#endif



attr_noinline void asm_setup_thread(void)
{
#if defined(INLINE_ASM_GCC_X86)
#if 0
	{
		unsigned short fpcw;
		unsigned mxcsr;
		__asm__ volatile("fstcw %0" : "=m"(fpcw));
		__asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
		debug("fpcw: %x, mxcsr: %x", fpcw, mxcsr);
	}
#endif
	{
		unsigned short fpcw = 0x37f;
		__asm__ volatile("fldcw %0" : : "m"(fpcw));
	}
#if defined(HAVE_X86_ASSEMBLER_SSE)
	if (likely(cpu_test_feature(CPU_FEATURE_sse))) {
		unsigned mxcsr = 0x1f80;
		__asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
	}
#endif
#endif
#if defined(INLINE_ASM_GCC_ARM)
	__asm__ volatile (ARM_ASM_PREFIX "vmsr fpscr, %0" : : "r"(0));
#endif
#if defined(INLINE_ASM_GCC_ARM64)
	__asm__ volatile (ARM_ASM_PREFIX "msr fpcr, %0" : : "r"(0UL));
#endif
}


static const struct {
	code_t orig;
	code_t alt;
	cpu_feature_mask_t mask;
} code_alttable[] = {
#define EMIT_ALTTABLE(orig, alt, flags)	{ orig, alt, flags },
#include "ipret.inc"
	{ 0, 0, 0 }
};
#define code_alttable_n		(n_array_elements(code_alttable) - 1)

code_t code_alt(code_t code)
{
	code_t ret;
	size_t s;
	binary_search(size_t, code_alttable_n, s, false, code_alttable[s].orig < code, break);
	ret = code;
	for (; s < code_alttable_n + uzero && code_alttable[s].orig == code; s++) {
		if ((cpu_feature_flags & code_alttable[s].mask) == code_alttable[s].mask)
			ret = code_alttable[s].alt;
	}
	/*if (code != ret) debug("code alt: %x -> %x", code, ret);*/
	return ret;
}

#ifdef DEBUG_BIST
static attr_noinline void verify_alttable(void)
{
	int i;
	/*debug("Alttable size: %x", (unsigned)code_alttable_n);*/
	for (i = 0; i < (int)code_alttable_n - 1; i++) {
		/*debug("Alttable: %x -> %x", code_alttable[i].orig, code_alttable[i].alt);*/
		if (unlikely(code_alttable[i].orig > code_alttable[i + 1].orig))
			internal(file_line, "verify_alttable: code_alttable is not sorted: 0x%x > 0x%x @ %d", (unsigned)code_alttable[i].orig, (unsigned)code_alttable[i + 1].orig, i);
		/*code_alt(code_alttable[i].orig);*/
	}
}
#else
#define verify_alttable()		do { } while (0)
#endif


void asm_init(void)
{
	uint32_t missing_features;

	verify_alttable();

	detection_failed = false;
#ifdef ARCH_ALPHA
	alpha_read_amask();
#endif
#ifdef ARCH_ARM
	arm_read_caps();
#endif
#ifdef ARCH_IA64
	ia64_read_cpuid();
#endif
#ifdef ARCH_LOONGARCH64
	loongarch_read_cpucfg();
#endif
#ifdef ARCH_S390
	s390_stfle();
#endif
#ifdef ARCH_X86
	test_eflags_bits();
	do_cpuid();
#endif
#if defined(ARCH_POWER) || defined(ARCH_RISCV64)
	os_signal_trap(SIGILL, sigill);
#endif
#define ASM_INC_DYNAMIC
#include "asm.inc"
#undef ASM_INC_DYNAMIC
#if defined(ARCH_POWER) || defined(ARCH_RISCV64)
	os_signal_restore(SIGILL);
#endif
	if (unlikely(detection_failed))
		cpu_feature_flags |= cpu_feature_static_flags;
	missing_features = cpu_feature_static_flags & ~cpu_feature_flags;
	if (unlikely(missing_features != 0)) {
		int first;
		int f;
		char *error;
		size_t error_l;
		str_init(&error, &error_l);
		str_add_string(&error, &error_l, "CPU doesn't have the following features: ");
		for (first = 1, f = 0; missing_features; missing_features >>= 1, f++) {
			if (missing_features & 1) {
				if (!first)
					str_add_string(&error, &error_l, ", ");
				first = 0;
				str_add_string(&error, &error_l, cpu_feature_names[f]);
			}
		}
		str_finish(&error, &error_l);
		fatal("%s", error);
	}
#ifdef DEBUG_INFO
	debug("static flags:  %x", cpu_feature_static_flags);
	debug("dynamic flags: %x", cpu_feature_flags);
#endif
	asm_setup_thread();

#ifdef DEBUG_CRASH_HANDLER
	os_signal_trap(SIGSEGV, crash);
	os_signal_trap(SIGBUS, crash);
	os_signal_trap(SIGILL, crash);
#endif
}

void asm_done(void)
{
}
