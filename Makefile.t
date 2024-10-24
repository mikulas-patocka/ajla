# Copyright (C) 2024 Mikulas Patocka
#
# This file is part of Ajla.
#
# Ajla is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# Ajla is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Ajla. If not, see <https://www.gnu.org/licenses/>.

bin_PROGRAMS=ajla
mylibdir=$(libdir)/$(PACKAGE)-$(VERSION)
fwlibdir=$(libdir)/$(PACKAGE)
nobase_mylib_DATA=FILES_INSTALL
AM_CPPFLAGS=-DAJLA_LIB='"$(mylibdir)"' -DAJLA_FRAMEWORKS='"$(fwlibdir)"'
ajla_SOURCES=ipret.c ipretc.c addrlock.c ajla.c amalloc.c args.c array.c arrayc.c arrayu.c arrayuc.c asm.c bist.c bistc.c builtin.c codegen.c codegenc.c data.c datac.c error.c fn_impl.c funct.c functc.c iomux.c iomux_ep.c iomux_kq.c ipfn.c ipfnc.c ipio.c ipioc.c layout.c mem_al.c mini-gmp.c module.c modulec.c mpint.c obj_reg.c os_dos.c os_os2.c os_posix.c os_util.c os_win32.c pcode.c pcodec.c profile.c program.c programc.c resolver.c rwlock.c save.c savec.c str.c task.c taskc.c th_haiku.c th_none.c th_os2.c th_posix.c th_win32.c tick.c timer.c tree.c type.c util.c addrlock.h ajla.h amalloc.h args.h arindex.h array.h arrayu.h arithm-b.h arithm-i.h arithm-r.h asm.h builtin.h cfg.h code-op.h codegen.h common.h compiler.h config-m.h data.h debug.h error.h fileline.h fn_impl.h funct.h iomux.h ipfn.h ipio.h ipunalg.h ipret.h layout.h list.h mem_al.h mini-gmp.h module.h mpint.h obj_reg.h options.h os.h os_util.h pcode-op.h pcode.h profile.h ptrcomp.h refcount.h resolver.h rwlock.h save.h str.h task.h thread.h tick.h timer.h tree.h type.h util.h version.h arithm-b.inc arithm-i.inc arithm-r.inc arm64-w.inc arm64-x.inc asm.inc asm-1.inc asm-alph.inc asm-arm.inc asm-hppa.inc asm-ia64.inc asm-loon.inc asm-ppc.inc asm-rv.inc asm-spar.inc asm-s390.inc asm-x86.inc c1-alpha.inc c1-arm.inc c1-arm64.inc c1-hppa.inc c1-ia64.inc c1-loong.inc c1-mips.inc c1-power.inc c1-riscv.inc c1-sparc.inc c1-s390.inc c1-x86.inc c2-alpha.inc c2-arm.inc c2-arm64.inc c2-hppa.inc c2-ia64.inc c2-loong.inc c2-mips.inc c2-power.inc c2-riscv.inc c2-sparc.inc c2-s390.inc c2-x86.inc cg-alu.inc cg-flags.inc cg-flcch.inc cg-frame.inc cg-ops.inc cg-ptr.inc cg-util.inc error.inc for-fix.inc for-int.inc for-real.inc iomux.inc ipio_ffi.inc ipret-1.inc ipret.inc ipret-a1.inc ipret-a2.inc ipret-a3.inc ipret-b1.inc os_com.inc os_os2_e.inc os_os2_s.inc os_pos_s.inc riscv-c.inc th_com.inc th_sig.inc
EXTRA_DIST=.gitignore Makefile.t clean dist-os2.sh dist-w64.sh fixup-configure rebuild selfopt.ajla selfopt-all.ajla swapend.ajla test.sh FILES_INSTALL FILES_DIST
install-data-hook:
	./ajla --nosave swapend.ajla $(mylibdir)/builtin.pcd
