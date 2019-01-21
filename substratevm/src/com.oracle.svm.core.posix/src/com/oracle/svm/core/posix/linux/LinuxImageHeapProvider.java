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

import static com.oracle.svm.core.Isolates.IMAGE_HEAP_WRITABLE_BEGIN;
import static com.oracle.svm.core.Isolates.IMAGE_HEAP_WRITABLE_END;
import static com.oracle.svm.core.posix.linux.ProcFSSupport.findMapping;
import static com.oracle.svm.core.util.PointerUtils.roundUp;

import com.oracle.svm.core.Isolates;
import com.oracle.svm.core.SubstrateOptions;
import com.oracle.svm.core.UnsafeAccess;
import com.oracle.svm.core.annotate.AutomaticFeature;
import com.oracle.svm.core.annotate.Uninterruptible;
import com.oracle.svm.core.c.CGlobalData;
import com.oracle.svm.core.c.CGlobalDataFactory;
import com.oracle.svm.core.c.function.CEntryPointErrors;
import com.oracle.svm.core.os.CopyingImageHeapProvider;
import com.oracle.svm.core.os.ImageHeapProvider;
import com.oracle.svm.core.os.VirtualMemoryProvider;
import com.oracle.svm.core.os.VirtualMemoryProvider.Access;
import com.oracle.svm.core.posix.headers.Fcntl;
import com.oracle.svm.core.posix.headers.LibC;
import com.oracle.svm.core.posix.headers.Stat;
import com.oracle.svm.core.posix.headers.Unistd;
import com.oracle.svm.core.util.UnsignedUtils;
import org.graalvm.compiler.api.replacements.Fold;
import org.graalvm.compiler.word.Word;
import org.graalvm.nativeimage.Feature;
import org.graalvm.nativeimage.ImageInfo;
import org.graalvm.nativeimage.ImageSingletons;
import org.graalvm.nativeimage.Platform;
import org.graalvm.nativeimage.Platforms;
import org.graalvm.nativeimage.StackValue;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CIntPointer;
import org.graalvm.nativeimage.c.type.CLongPointer;
import org.graalvm.nativeimage.c.type.WordPointer;
import org.graalvm.word.LocationIdentity;
import org.graalvm.word.Pointer;
import org.graalvm.word.PointerBase;
import org.graalvm.word.UnsignedWord;
import org.graalvm.word.WordFactory;

@AutomaticFeature
@Platforms({Platform.LINUX.class})
class LinuxImageHeapProviderFeature implements Feature {
    @Override
    public void beforeAnalysis(BeforeAnalysisAccess access) {
        if (Platform.includedIn(Platform.LINUX_AMD64.class) && SubstrateOptions.UseCOWIsolateHeaps.getValue()) {
            ImageSingletons.add(ImageHeapProvider.class, new LinuxImageHeapProvider());
        } else {
            ImageSingletons.add(ImageHeapProvider.class, new CopyingImageHeapProvider());
        }
    }
}

/**
 * An optimal image heap provider for Linux which creates isolate image heaps
 * that retain the copy-on-write, lazy loading and reclamation semantics
 * provided by the original heap's backing resource.
 *
 * This is accomplished by discovering the backing executable or shared object
 * file the kernel has mmapped to the original heap image virtual address, as
 * well as the location in the file storing the original heap. A new memory map
 * is created to a new virtual range pointing to this same location. This allows
 * the kernel to share the same physical pages between multiple heaps that have
 * not been modified, as well as lazily load them only when needed.
 *
 * The implementation avoids dirtying the pages of the original, and only
 * referencing what is strictly required.
 *
 * This provider falls back to the POSIX friendly
 * <code>CopyImageHeapProvider</code> if either the architecture is not
 * supported, or an error occurs during the mapping process.
 */
public class LinuxImageHeapProvider extends CopyingImageHeapProvider {
    private static final CGlobalData<CCharPointer> SELF_EXE = CGlobalDataFactory.createCString("/proc/self/exe");
    private static final CGlobalData<CCharPointer> MAPS = CGlobalDataFactory.createCString("/proc/self/maps");
    private static final CGlobalData<Word> DYNAMIC = CGlobalDataFactory.forSymbol("_DYNAMIC");
    private static final CGlobalData<Pointer> OBJECT_FD = CGlobalDataFactory.createWord(WordFactory.signed(-1), null);
    private static final CGlobalData<Pointer> FD_OFFSET = CGlobalDataFactory.createWord(WordFactory.signed(-1), null);
    private static final CGlobalData<Pointer> SVM_BASE = CGlobalDataFactory.createWord(WordFactory.signed(-1), null);

    private static final int MAX_PATHLEN = 4096;

    private static final int DT_RELA = 7;
    private static final int DT_REL = 17;
    private static final int DT_RELASZ = 8;
    private static final int DT_RELSZ = 18;

    @Fold
    static boolean isExecutable() {
        return ImageInfo.isExecutable();
    }

    @Override
    @Uninterruptible(reason = "Called during isolate initialization.")
    public int initialize(PointerBase begin, UnsignedWord reservedSize, WordPointer basePointer, WordPointer endPointer) {
        int result = cowInitialize(begin, reservedSize, basePointer, endPointer);
        if (result != CEntryPointErrors.NO_ERROR) {
            return super.initialize(begin, reservedSize, basePointer, endPointer);
        }

        return result;
    }

    @Uninterruptible(reason = "Called during isolate initialization.")
    private int cowInitialize(PointerBase begin, UnsignedWord reservedSize, WordPointer basePointer, WordPointer endPointer) {
        Word imageHeapBegin = Isolates.IMAGE_HEAP_BEGIN.get();
        Word imageHeapSize = Isolates.IMAGE_HEAP_END.get().subtract(imageHeapBegin);
        if (begin.isNonNull() && reservedSize.belowThan(imageHeapSize)) {
            return CEntryPointErrors.UNSPECIFIED;
        }

        boolean executable = isExecutable();

        // Reuse the already loaded file descriptor and discovered offset for
        // all subsequent isolate initializations. To avoid stalling threads we
        // intentionally allow for racing during first-time initialization. It's
        // the lesser of evils, since the overhead of proc parsing and required
        // i/o is nominal, due to its virtual nature.
        //
        // However, we ensure this remains temporary and consensus is quickly
        // reached on a single FD,
        UnsafeAccess.UNSAFE.loadFence();
        int fd = (int)OBJECT_FD.get().readLong(0);

        if (fd != -1) {
           return createMapping(begin, basePointer, endPointer, imageHeapBegin, imageHeapSize, fd, FD_OFFSET.get().readLong(0), !executable);
        }

        int mapFD = Fcntl.NoTransitions.open(MAPS.get(), Fcntl.O_RDONLY(), 0);
        if (mapFD == -1) {
            return CEntryPointErrors.MAP_HEAP_FAILED;
        }

        final CCharPointer buffer = LibC.malloc(WordFactory.unsigned(MAX_PATHLEN));
        final CLongPointer startAddr = StackValue.get(CLongPointer.class);
        final CLongPointer offset = StackValue.get(CLongPointer.class);
        final CIntPointer dev = StackValue.get(CIntPointer.class);
        final CLongPointer inode = StackValue.get(CLongPointer.class);

        boolean found = findMapping(mapFD, buffer, MAX_PATHLEN, imageHeapBegin.rawValue(), startAddr, offset, dev, inode, !executable);
        Unistd.NoTransitions.close(mapFD);

        if (! found) {
            LibC.free(buffer);
            return CEntryPointErrors.MAP_HEAP_FAILED;
        }

        fd = Fcntl.NoTransitions.open(executable ? SELF_EXE.get() : buffer, Fcntl.O_RDONLY(), 0);
        LibC.free(buffer);

        if (fd == -1) {
            return CEntryPointErrors.MAP_HEAP_FAILED;
        }

        // Unfortunately, in the case of a shared library, we must open the
        // library by the registered file name, since we don't have a usable
        // equivalent of /proc/self/exe, which remains even if the file is
        // deleted, since it keeps an inode reference active. The kernel does
        // provide a similar notion in /proc/map_files, but directly opening
        // those entries intentionally requires CAP_SYS_ADMIN, out of security
        // concerns (see discussion in https://lkml.org/lkml/2015/5/19/896)
        //
        // In practice, this is unlikely to be a problem since the window for an
        // unlink race is tiny. We immediately read the file in the earliest
        // stages of start, and we cache the FD after. Once we have the FD we
        // can still access the mapped file even after it has been deleted.
        //
        // As a precaution we verify the file we open matches the inode
        // associated with the true mapped in original. In the case it does
        // not we must abort and fall back to the copy strategy. In the case of
        // native executables, it will always match due to /proc/self/exe.
        if (! executable) {
            Stat.stat stat = StackValue.get(Stat.stat.class);
            if (Stat.fstat_no_transition(fd, stat) != 0 && stat.st_ino() != inode.read() && stat.st_dev() != dev.read()) {
                Unistd.NoTransitions.close(fd);
                return CEntryPointErrors.MAP_HEAP_FAILED;
            }
        }

        long newOffset = offset.read() + (imageHeapBegin.rawValue() - startAddr.read());

        if (!FD_OFFSET.get().logicCompareAndSwapLong(0, -1, newOffset, LocationIdentity.ANY_LOCATION)) {
            // Another thread won, busy-wait until we can use it's descriptor
            Unistd.NoTransitions.close(fd);
            do {
                UnsafeAccess.UNSAFE.loadFence();
                fd = (int)OBJECT_FD.get().readLong(0);
            } while (fd == -1);
            newOffset = FD_OFFSET.get().readLong(0);
        } else {
            SVM_BASE.get().writeLong(0, startAddr.read() - offset.read());
            OBJECT_FD.get().writeLong(0, fd);
            // Ensure we have a Store-Load barrier to match up with loads
            // so that we get volatile access semantics
            UnsafeAccess.UNSAFE.fullFence();
        }

        return createMapping(begin, basePointer, endPointer, imageHeapBegin, imageHeapSize, fd, newOffset, !executable);
    }

    @Uninterruptible(reason = "Called during isolate initialization.")
    private int createMapping(PointerBase begin, WordPointer basePointer, WordPointer endPointer, Word imageHeapBegin, Word imageHeapSize, int fd, long offset, boolean patch) {

        Pointer heap = VirtualMemoryProvider.get().mapFile(begin, imageHeapSize, WordFactory.unsigned(fd), WordFactory.unsigned(offset), Access.READ | Access.WRITE);
        if (heap.isNull()) {
            return CEntryPointErrors.MAP_HEAP_FAILED;
        }

        if (patch) {
            // In the case of a shared library, since we directly mmap the
            // segment outside of LD, we must perform the relocations ourselves.
            Word end = imageHeapBegin.add(imageHeapSize);
            if (! patchRelocations(imageHeapBegin, end, heap)) {
                return CEntryPointErrors.MAP_HEAP_FAILED;
            }
        }

        UnsignedWord pageSize = VirtualMemoryProvider.get().getGranularity();
        UnsignedWord writableBeginPageOffset = UnsignedUtils.roundDown(IMAGE_HEAP_WRITABLE_BEGIN.get().subtract(imageHeapBegin), pageSize);
        if (writableBeginPageOffset.aboveThan(0)) {
            if (VirtualMemoryProvider.get().protect(heap, writableBeginPageOffset, Access.READ) != 0) {
                return CEntryPointErrors.PROTECT_HEAP_FAILED;
            }
        }
        UnsignedWord writableEndPageOffset = UnsignedUtils.roundUp(IMAGE_HEAP_WRITABLE_END.get().subtract(imageHeapBegin), pageSize);
        if (writableEndPageOffset.belowThan(imageHeapSize)) {
            Pointer afterWritableBoundary = heap.add(writableEndPageOffset);
            Word afterWritableSize = imageHeapSize.subtract(writableEndPageOffset);
            if (VirtualMemoryProvider.get().protect(afterWritableBoundary, afterWritableSize, Access.READ) != 0) {
                return CEntryPointErrors.PROTECT_HEAP_FAILED;
            }
        }

        basePointer.write(heap);
        if (endPointer.isNonNull()) {
            endPointer.write(roundUp(heap.add(imageHeapSize), pageSize));
        }

        return CEntryPointErrors.NO_ERROR;
    }

    @Uninterruptible(reason = "Called during isolate initialization.")
    private boolean patchRelocations(Word imageHeapBegin, Word end, Pointer heap) {
        // Utilize the ELF dynamic table which is available via the _DYNAMIC
        // symbol reference. The code in this routine is 64 bit architecture
        // specific, due to it's usage of ELF 64 structures.
        //
        // Dynamic table
        // {
        //   sint64   d_tag;  /* Dynamic entry type */
        //   union
        //   {
        //     uint64 d_val;  /* Integer value */
        //     uint64 d_ptr;  /* Address value */
        //   }
        // }

        Pointer pointer = DYNAMIC.get();
        Pointer rela = nullPointer();
        Pointer rel = nullPointer();
        long relaSize = 0;
        long relSize = 0;

        loop:
        for (int i = 0; ; i += 16) {
            int tag = (int) pointer.readLong(i);

            switch (tag) {
                case DT_RELA:
                    // Unlike the storage format, the linker converts these
                    // offsets to actual addresses post-load
                    rela = WordFactory.pointer(pointer.readLong(i + 8));
                    break;
                case DT_REL:
                    rel = WordFactory.pointer(pointer.readLong(i + 8));
                    break;
                case DT_RELASZ:
                    relaSize = pointer.readLong(i + 8);
                    break;
                case DT_RELSZ:
                    relSize = pointer.readLong(i + 8);
                    break;
                case 0:
                    break loop;

            }
        }

        boolean result = true;

        if (rela.isNonNull()) {
            result &= patchRelocationSection(rela, relaSize, 24, imageHeapBegin, end, heap);
        }

        // Handle REL tables as well, even though they are unlikely to be used
        if (rel.isNonNull()) {
           result &= patchRelocationSection(rel, relSize, 16, imageHeapBegin, end, heap);
        }

        return result;
    }

    @Uninterruptible(reason = "Called during isolate initialization.")
    private boolean patchRelocationSection(Pointer table, long size, int entrySize, Word imageHeapBegin, Word imageHeapEnd, Pointer heap) {
        Pointer base = WordFactory.pointer(SVM_BASE.get().readLong(0));
        Pointer end = table.add(WordFactory.unsigned(size));

        // Instead of reimplementing every relocation type mechanism, we take a
        // difference approach, and copy the already computed value from our
        // source region. This simplifies the implementation and maintenance
        // burden, since we only have to care about the word length of each
        // relocation type. Aside from requiring 64-bit, only the lookup portion
        // is CPU architecture specific.
        while (table.belowThan(end)) {
            // Relocation table Entry
            // {
            //     uint64  r_offset;   /* Address offset from 0 */
            //     uint64  r_info;
            //     /* {
            //         lower 32 = relocation type (processor specific)
            //         upper 32 = symbol index (ignore)
            //     */ }
            //     uint64  r_addend;   /* Only present in RELA table */
            // }

            Pointer source = base.add(WordFactory.unsigned(table.readLong(0)));
            if (source.aboveOrEqual(imageHeapBegin) && source.belowThan(imageHeapEnd)) {

                int type = (int) table.readLong(8); // Read the full qword and truncate even
                                                    // though we only need the lower 4 bytes
                                                    // to keep this non-endian specific.
                int bytes = ArchRelocationInfo.get().lookupFieldSize(type);

                if (bytes < 0 || source.add(bytes).aboveThan(imageHeapEnd)) {
                    // Patching shouldn't overflow, abort if it does.
                    // Also abort if the relocation type is unsupported
                    // or unknown to be safe. Copy symbol operations are an
                    // example of the former. They aren't necessary since the
                    // native image process and ld linkage doesn't generate
                    // them. In particular the linker utilizes simpler direct
                    // relocations. However, it's best to handle all known types
                    // in case the user has post-edited or utilized custom
                    // linkage scripts.
                    return false;
                }

                Pointer target = heap.add(source.subtract(imageHeapBegin));
                switch (bytes) {
                    case 8:
                        target.writeLong(0, source.readLong(0));
                        break;
                    case 4:
                        target.writeInt(0, source.readInt(0));
                        break;
                    case 2:
                        target.writeShort(0, source.readShort(0));
                        break;
                    case 1:
                        target.writeByte(0, source.readByte(0));
                        break;
                    case 0:
                        break;
                    default:
                        return false;
                }

            }

            table = table.add(entrySize);
        }

        return true;
    }

    @Uninterruptible(reason = "Called from uninterruptible code.")
    private static <T extends PointerBase> T nullPointer() {
        return WordFactory.nullPointer();
    }
}