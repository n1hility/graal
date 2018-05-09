/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
package com.oracle.truffle.dsl.processor.java;

import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.function.Function;
import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.ModuleElement;
import javax.lang.model.element.TypeElement;

final class ModuleCache {
    private static final Map<ProcessingEnvironment, Map<String, ModuleElement>> moduleCacheCleaner = new WeakHashMap<>();

    private ModuleCache() {
        throw new IllegalStateException("Cannot instantiate.");
    }

    static TypeElement getTypeElement(final ProcessingEnvironment processingEnv, final CharSequence typeName) {
        if (processingEnv.getSourceVersion().compareTo(SourceVersion.RELEASE_9) < 0) {
            return processingEnv.getElementUtils().getTypeElement(typeName);
        }
        final Map<String, ModuleElement> moduleCache = moduleCacheCleaner.computeIfAbsent(processingEnv, new Function<ProcessingEnvironment, Map<String, ModuleElement>>() {
            @Override
            public Map<String, ModuleElement> apply(ProcessingEnvironment t) {
                return new HashMap<>();
            }
        });
        final String typeNameString = typeName.toString();
        ModuleElement moduleElement = moduleCache.get(typeNameString);
        if (moduleElement == null) {
            final TypeElement typeElement = processingEnv.getElementUtils().getTypeElement(typeName);
            if (typeElement != null) {
                moduleElement = processingEnv.getElementUtils().getModuleOf(typeElement);
                moduleCache.put(typeNameString, moduleElement);
            }
            return typeElement;
        } else {
            return processingEnv.getElementUtils().getTypeElement(moduleElement, typeName);
        }
    }
}