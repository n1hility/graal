/*
 * Copyright (c) 2019, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.oracle.svm.core.posix.linux;

import com.oracle.svm.core.annotate.Uninterruptible;
import org.graalvm.compiler.api.replacements.Fold;
import org.graalvm.nativeimage.Platform;
import org.graalvm.nativeimage.Platforms;

@Platforms(Platform.LINUX.class)
abstract class ArchRelocationInfo {
    /**
     * Returns the field size utilized by the relocation type for this
     * architecture, or -1 if the type is unsupported or unknown. A zero return
     * value is legal, and means the relocation can be skipped.
     *
     * @param type the relocation type tag
     * @return the number of bytes that this relocation type operates on, or -1
     *         if the type is not supported or unknown.
     */
    abstract int lookupFieldSize(int type);

    @Fold
    static ArchRelocationInfo get() {
        // Currently only AMD64 is supported
        return new AMD64ArchRelocaitonInfo();
    }
}

class AMD64ArchRelocaitonInfo extends ArchRelocationInfo {

    private static final int R_X86_64_NONE = 0;
    private static final int R_X86_64_64 = 1;
    private static final int R_X86_64_PC32 = 2;
    private static final int R_X86_64_GOT32 = 3;
    private static final int R_X86_64_PLT32 = 4;
    private static final int R_X86_64_COPY = 5;
    private static final int R_X86_64_GLOB_DAT = 6;
    private static final int R_X86_64_JUMP_SLOT = 7;
    private static final int R_X86_64_RELATIVE = 8;
    private static final int R_X86_64_GOTPCREL = 9;
    private static final int R_X86_64_32 = 10;
    private static final int R_X86_64_32S = 11;
    private static final int R_X86_64_16 = 12;
    private static final int R_X86_64_PC16 = 13;
    private static final int R_X86_64_8 = 14;
    private static final int R_X86_64_PC8 = 15;
    private static final int R_X86_64_DTPMOD64 = 16;
    private static final int R_X86_64_DTPOFF64 = 17;
    private static final int R_X86_64_TPOFF64 = 18;
    private static final int R_X86_64_TLSGD = 19;
    private static final int R_X86_64_TLSLD = 20;
    private static final int R_X86_64_DTPOFF32 = 21;
    private static final int R_X86_64_GOTTPOFF = 22;
    private static final int R_X86_64_TPOFF32 = 23;
    private static final int R_X86_64_PC64 = 24;
    private static final int R_X86_64_GOTOFF64 = 25;
    private static final int R_X86_64_GOTPC32 = 26;
    private static final int R_X86_64_SIZE32 = 32;
    private static final int R_X86_64_SIZE64 = 33;
    private static final int R_X86_64_GOTPC32_TLSDESC = 34;
    private static final int R_X86_64_TLSDESC_CALL = 35;
    private static final int R_X86_64_TLSDESC = 36;
    private static final int R_X86_64_IRELATIVE = 37;
    private static final int R_X86_64_RELATIVE64 = 38;
    private static final int R_X86_64_GOTPCRELX = 41;
    private static final int R_X86_64_REX_GOTPCRELX = 42;

    @Uninterruptible(reason = "Called from uninterruptible code.")
    @Override
    int lookupFieldSize(int type) {

        /*
         *  Latest X86-64 System V ABI:
         *
         *  https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI
         */
        switch (type) {
            case R_X86_64_64:
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
            case R_X86_64_RELATIVE:
            case R_X86_64_DTPMOD64:
            case R_X86_64_DTPOFF64:
            case R_X86_64_TPOFF64:
            case R_X86_64_PC64:
            case R_X86_64_GOTOFF64:
            case R_X86_64_SIZE64:
            case R_X86_64_TLSDESC:
            case R_X86_64_IRELATIVE:
            case R_X86_64_RELATIVE64:
                return 8;
            case R_X86_64_PC32:
            case R_X86_64_GOT32:
            case R_X86_64_PLT32:
            case R_X86_64_GOTPCREL:
            case R_X86_64_32:
            case R_X86_64_32S:
            case R_X86_64_TLSGD:
            case R_X86_64_TLSLD:
            case R_X86_64_DTPOFF32:
            case R_X86_64_GOTTPOFF:
            case R_X86_64_TPOFF32:
            case R_X86_64_GOTPC32:
            case R_X86_64_SIZE32:
            case R_X86_64_GOTPC32_TLSDESC:
            case R_X86_64_GOTPCRELX:
            case R_X86_64_REX_GOTPCRELX:
                return 4;
            case R_X86_64_16:
            case R_X86_64_PC16:
                return 2;
            case R_X86_64_8:
            case R_X86_64_PC8:
                return 1;
            case R_X86_64_NONE:
            case R_X86_64_TLSDESC_CALL:
                return 0;
            case R_X86_64_COPY:
                // Copy is not necessary (see note in
                //    LinuxImageHeapProvider.patchRelocationSection())
            default:
                return -1;
        }
    }
}
