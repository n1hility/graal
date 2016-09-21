/*
 * Copyright (c) 2016, Oracle and/or its affiliates. All rights reserved.
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
package com.oracle.truffle.api.instrumentation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.oracle.truffle.api.nodes.Node;
import com.oracle.truffle.api.source.Source;
import com.oracle.truffle.api.source.SourceSection;

/**
 * A source section filter represents an expression for a subset of tagged source sections that are
 * used in an Truffle interpreter.
 * <p>
 * Start building event filters by calling {@link SourceSectionFilter#newBuilder()} and complete
 * them by calling {@link Builder#build()}.
 *
 * @see SourceSectionFilter#newBuilder()
 * @see Instrumenter#attachFactory(SourceSectionFilter, ExecutionEventNodeFactory)
 * @see Instrumenter#attachListener(SourceSectionFilter, ExecutionEventListener)
 * @since 0.12
 */
public final class SourceSectionFilter {

    /**
     * A filter that matches everything.
     *
     * @since 0.18
     */
    public static final SourceSectionFilter ANY = newBuilder().build();

    private final EventFilterExpression[] expressions;

    private SourceSectionFilter(EventFilterExpression[] expressions) {
        this.expressions = expressions;
    }

    /**
     * Creates a new {@link SourceSectionFilter} expression using a {@link Builder builder} pattern.
     * Individual builder statements are interpreted as conjunctions (AND) while multiple parameters
     * for individual filter expressions are treated as disjunctions (OR). To create the final
     * filter finalize the expression using {@link Builder#build()}.
     *
     * @see Builder#sourceIs(Source...)
     * @see Builder#mimeTypeIs(String...)
     * @see Builder#tagIs(Class...)
     * @see Builder#tagIsNot(Class...)
     * @see Builder#sourceSectionEquals(SourceSection...)
     * @see Builder#indexIn(int, int)
     * @see Builder#lineIn(int, int)
     * @see Builder#lineIs(int)
     * @see Builder#build()
     *
     * @return a new builder to create new {@link SourceSectionFilter} instances
     * @since 0.12
     */
    public static Builder newBuilder() {
        return new SourceSectionFilter(null).new Builder();
    }

    /**
     * @return the filter expressions in a human readable form for debugging.
     * @since 0.12
     */
    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("SourceSectionFilter[");
        String sep = "";
        for (EventFilterExpression expression : expressions) {
            b.append(sep);
            b.append(expression.toString());
            sep = " and ";
        }
        b.append("]");
        return b.toString();
    }

    // implementation
    Set<Class<?>> getReferencedTags() {
        Set<Class<?>> usedTags = new HashSet<>();
        for (EventFilterExpression expression : expressions) {
            expression.collectReferencedTags(usedTags);
        }
        return usedTags;
    }

    boolean isSourceOnly() {
        for (EventFilterExpression eventFilterExpression : expressions) {
            if (!eventFilterExpression.isSourceOnly()) {
                return false;
            }
        }
        return true;
    }

    boolean isInstrumentedRoot(Set<Class<?>> providedTags, SourceSection rootSourceSection) {
        for (EventFilterExpression exp : expressions) {
            if (!exp.isRootIncluded(providedTags, rootSourceSection)) {
                return false;
            }
        }
        return true;
    }

    boolean isInstrumentedNode(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
        if (sourceSection == null) {
            return false;
        }
        for (EventFilterExpression exp : expressions) {
            if (!exp.isIncluded(providedTags, instrumentedNode, sourceSection)) {
                return false;
            }
        }
        return true;
    }

    boolean isInstrumentedSource(Source source) {
        if (source == null) {
            return false;
        }
        for (EventFilterExpression exp : expressions) {
            assert exp.isSourceOnly();
            if (!exp.isSourceIncluded(source)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Configure your own {@link SourceSectionFilter} before creating its instance. Specify various
     * parameters by calling individual {@link Builder} methods. When done, call {@link #build()}.
     *
     * @since 0.12
     */
    public final class Builder {
        private List<EventFilterExpression> expressions = new ArrayList<>();

        private Builder() {
        }

        /**
         * Add a filter for all source sections that reference one of the given sources.
         *
         * @since 0.12
         */
        public Builder sourceIs(Source... source) {
            verifyNotNull(source);
            expressions.add(new EventFilterExpression.SourceIs(source));
            return this;
        }

        /**
         * Adds custom predicate to filter inclusion of {@link Source sources}. The predicate must
         * always return the same result for a source instance otherwise the behavior is undefined.
         * The predicate should be able run on multiple threads at the same time.
         *
         * @param predicate a test for inclusion
         * @since 0.17
         */
        public Builder sourceIs(SourcePredicate predicate) {
            if (predicate == null) {
                throw new IllegalArgumentException("SourcePredicate must not be null.");
            }
            expressions.add(new EventFilterExpression.SourceFilterIs(predicate));
            return this;
        }

        /**
         * Add a filter for all source sections that declare one of the given mime-types. Mime-types
         * which are compared must match exactly one of the mime-types specified by the target guest
         * language.
         *
         * @param mimeTypes matches one of the given mime types
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder mimeTypeIs(String... mimeTypes) {
            verifyNotNull(mimeTypes);
            expressions.add(new EventFilterExpression.MimeTypeIs(mimeTypes));
            return this;
        }

        /**
         * Add a filter for all source sections that are tagged with one of the given String tags.
         *
         * @param tags matches one of the given tags
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder tagIs(Class<?>... tags) {
            verifyNotNull(tags);
            expressions.add(new EventFilterExpression.TagIs(tags));
            return this;
        }

        /**
         * Add a filter for all sources sections that declare not one of the given String tags.
         *
         * @param tags matches not one of the given tags
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder tagIsNot(Class<?>... tags) {
            verifyNotNull(tags);
            expressions.add(new Not(new EventFilterExpression.TagIs(tags)));
            return this;
        }

        /**
         * Add a filter for all sources sections that equal one of the given source sections.
         *
         * @param section matches one of the given source sections
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder sourceSectionEquals(SourceSection... section) {
            verifyNotNull(section);
            expressions.add(new EventFilterExpression.SourceSectionEquals(section));
            return this;
        }

        /**
         * Add a filter for all root sources sections that equal one of the given source sections.
         * All descendant source sections of a matching root source section are included in the
         * filter. This can mean in the dynamic language domain that all nodes of a function for
         * which the root source section matches the given source section is instrumented but its
         * inner functions and its nodes are not instrumented.
         *
         * @param section matches one of the given root source sections
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder rootSourceSectionEquals(SourceSection... section) {
            verifyNotNull(section);
            expressions.add(new EventFilterExpression.RootSourceSectionEquals(section));
            return this;
        }

        /**
         * Add a filter for all sources sections which indices are not contained in one of the given
         * index ranges.
         *
         * @param ranges matches indices that are not contained one of the given index ranges
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder indexNotIn(IndexRange... ranges) {
            verifyNotNull(ranges);
            expressions.add(new Not(new EventFilterExpression.IndexIn(ranges)));
            return this;
        }

        /**
         * Add a filter for all sources sections which indices are contained in one of the given
         * index ranges.
         *
         * @param ranges matches indices that are contained one of the given index ranges
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder indexIn(IndexRange... ranges) {
            verifyNotNull(ranges);
            expressions.add(new EventFilterExpression.IndexIn(ranges));
            return this;
        }

        /**
         * Add a filter for all sources sections where the index is inside a startIndex (inclusive)
         * plus a given length (exclusive).
         *
         * @param startIndex the start index (inclusive)
         * @param length the number of matched characters
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder indexIn(int startIndex, int length) {
            return indexIn(IndexRange.byLength(startIndex, length));
        }

        /**
         * Add a filter for all sources sections which lines are contained in one of the given index
         * ranges. Line indices must be greater or equal to <code>1</code>.
         *
         * @param ranges matches lines that are contained one of the given index ranges
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder lineIn(IndexRange... ranges) {
            verifyLineIndices(ranges);
            expressions.add(new EventFilterExpression.LineIn(ranges));
            return this;
        }

        /**
         * Add a filter for all sources sections which lines are not contained in one of the given
         * index ranges. Line indices must be greater or equal to <code>1</code>.
         *
         * @param ranges matches lines that are not contained one of the given index ranges
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder lineNotIn(IndexRange... ranges) {
            verifyLineIndices(ranges);
            expressions.add(new Not(new EventFilterExpression.LineIn(ranges)));
            return this;
        }

        /**
         * Add a filter for all sources sections where the line is inside a startLine (first index
         * inclusive) plus a given length (last index exclusive).
         *
         * @param startLine the start line (inclusive)
         * @param length the number of matched lines
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder lineIn(int startLine, int length) {
            return lineIn(IndexRange.byLength(startLine, length));
        }

        /**
         * Add a filter for all sources sections start in one of the given index ranges. Line
         * indices must be greater or equal to <code>1</code>.
         *
         * @param ranges matches lines that start in one of the given index ranges
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder lineStartsIn(IndexRange... ranges) {
            verifyLineIndices(ranges);
            expressions.add(new EventFilterExpression.LineStartsIn(ranges));
            return this;
        }

        /**
         * Add a filter for all sources sections end in one of the given index ranges. Line indices
         * must be greater or equal to <code>1</code>.
         *
         * @param ranges matches lines that end in one of the given index ranges
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder lineEndsIn(IndexRange... ranges) {
            verifyLineIndices(ranges);
            expressions.add(new EventFilterExpression.LineEndsIn(ranges));
            return this;
        }

        private void verifyLineIndices(IndexRange... ranges) {
            verifyNotNull(ranges);
            for (IndexRange indexRange : ranges) {
                if (indexRange.startIndex < 1) {
                    throw new IllegalArgumentException(String.format("Start line indices must be >= 1 but were %s.", indexRange.startIndex));
                }
            }
        }

        /**
         * Add a filter for all sources sections where the line is exactly the given line. Line
         * indices must be greater or equal to <code>1</code>. *
         *
         * @param line the line to be matched
         * @return the builder to chain calls
         * @since 0.12
         */
        public Builder lineIs(int line) {
            return lineIn(line, 1);
        }

        /**
         * Finalizes and constructs the {@link SourceSectionFilter} instance.
         *
         * @return the built filter expression
         * @since 0.12
         */
        public SourceSectionFilter build() {
            Collections.sort(expressions);
            return new SourceSectionFilter(expressions.toArray(new EventFilterExpression[0]));
        }

        private void verifyNotNull(Object[] values) {
            if (values == null) {
                throw new IllegalArgumentException("Given arguments must not be null.");
            }
            for (int i = 0; i < values.length; i++) {
                if (values[i] == null) {
                    throw new IllegalArgumentException("None of the given argument values must be null.");
                }
            }
        }

    }

    /**
     * Represents a predicate for source objects.
     *
     * @since 0.17
     */
    public interface SourcePredicate {

        /**
         * Returns <code>true</code> if the given source should be tested positive and
         * <code>false</code> if the sources should be filtered.
         *
         * @param source the source object to filter
         * @since 0.17
         */
        boolean test(Source source);
    }

    /**
     * Represents a range between two indices within a {@link SourceSectionFilter source section
     * filter}. Instances are immutable.
     *
     * @see SourceSectionFilter
     * @see #between(int, int)
     * @see #byLength(int, int)
     * @since 0.12
     */
    public static final class IndexRange {

        final int startIndex;
        final int endIndex;

        private IndexRange(int startIndex, int endIndex) {
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        /**
         * Constructs a new index range between one a first index inclusive and a second index
         * exclusive. Parameters must comply <code>startIndex >= 0</code> and
         * <code>startIndex <= endIndex</code>.
         *
         * @param startIndex the start index (inclusive)
         * @param endIndex the end index (inclusive)
         * @return a new index range
         * @throws IllegalArgumentException if parameter invariants are violated
         * @since 0.12
         */
        public static IndexRange between(int startIndex, int endIndex) {
            if (startIndex < 0) {
                throw new IllegalArgumentException(String.format("The argument startIndex must be positive but is %s.", startIndex));
            } else if (endIndex < startIndex) {
                throw new IllegalArgumentException(String.format("Invalid range %s:%s.", startIndex, endIndex));
            }
            return new IndexRange(startIndex, endIndex);
        }

        /**
         * Constructs a new index range with a given first index inclusive and a given length.
         * Parameters must comply <code>startIndex >= 0</code> and <code>length >= 0</code>.
         *
         * @param startIndex the start index (inclusive)
         * @param length the length of the range
         * @return a new index range
         * @throws IllegalArgumentException if parameter invariants are violated
         * @since 0.12
         */
        public static IndexRange byLength(int startIndex, int length) {
            if (length < 0) {
                throw new IllegalArgumentException(String.format("The argument length must be positive but is %s.", length));
            } else if (startIndex < 0) {
                throw new IllegalArgumentException(String.format("The argument startIndex must be positive but is %s.", startIndex));
            }
            return new IndexRange(startIndex, startIndex + length);
        }

        boolean contains(int otherStartIndex, int otherEndIndex) {
            return startIndex <= otherEndIndex && otherStartIndex < endIndex;
        }

        /**
         * @return a human readable version of the index range
         * @since 0.12
         */
        @Override
        public String toString() {
            return "[" + startIndex + "-" + endIndex + "[";
        }

    }

    private abstract static class EventFilterExpression implements Comparable<EventFilterExpression> {

        protected abstract int getOrder();

        void collectReferencedTags(@SuppressWarnings("unused") Set<Class<?>> collectTags) {
            // default implementation does nothing
        }

        boolean isSourceIncluded(@SuppressWarnings("unused") Source source) {
            return false;
        }

        abstract boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection);

        abstract boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection);

        boolean isSourceOnly() {
            return false;
        }

        public final int compareTo(EventFilterExpression o) {
            return o.getOrder() - getOrder();
        }

        static void appendRanges(StringBuilder builder, IndexRange[] ranges) {
            String sep = "";
            for (IndexRange range : ranges) {
                builder.append(sep).append(range);
                sep = " or ";
            }
        }

        private static final class SourceFilterIs extends EventFilterExpression {

            private final SourcePredicate predicate;

            SourceFilterIs(SourcePredicate predicate) {
                this.predicate = predicate;
            }

            @Override
            boolean isSourceOnly() {
                return true;
            }

            @Override
            boolean isSourceIncluded(Source src) {
                if (src == null) {
                    return false;
                }
                return predicate.test(src);
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSourceSection) {
                if (rootSourceSection == null) {
                    return true;
                }
                return isSourceIncluded(rootSourceSection.getSource());
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                return isSourceIncluded(sourceSection.getSource());
            }

            @Override
            protected int getOrder() {
                return 1;
            }

            @Override
            public String toString() {
                return String.format("source is included by custom filter %s", predicate.toString());
            }
        }

        private static final class SourceIs extends EventFilterExpression {

            private final Source[] sources;

            SourceIs(Source... source) {
                this.sources = source;
            }

            @Override
            boolean isSourceOnly() {
                return true;
            }

            @Override
            boolean isSourceIncluded(Source src) {
                for (Source otherSource : sources) {
                    if (src == otherSource) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSourceSection) {
                if (rootSourceSection == null) {
                    return true;
                }
                return isSourceIncluded(rootSourceSection.getSource());
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                return isSourceIncluded(sourceSection.getSource());
            }

            @Override
            protected int getOrder() {
                return 1;
            }

            @Override
            public String toString() {
                return String.format("source is %s", Arrays.toString(sources));
            }
        }

        private static final class MimeTypeIs extends EventFilterExpression {

            private final String[] mimeTypes;

            MimeTypeIs(String... mimeTypes) {
                this.mimeTypes = mimeTypes;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSourceSection) {
                if (rootSourceSection == null) {
                    return true;
                }
                return isSourceIncluded(rootSourceSection.getSource());
            }

            @Override
            boolean isSourceOnly() {
                return true;
            }

            @Override
            boolean isSourceIncluded(Source source) {
                String mimeType = source.getMimeType();
                if (mimeType != null) {
                    for (String otherMimeType : mimeTypes) {
                        if (otherMimeType.equals(mimeType)) {
                            return true;
                        }
                    }
                }
                return false;
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                return isSourceIncluded(sourceSection.getSource());
            }

            @Override
            protected int getOrder() {
                return 2;
            }

            @Override
            public String toString() {
                return String.format("mime-type is one-of %s", Arrays.toString(mimeTypes));
            }
        }

        private static Class<?>[] checkTags(Class<?>[] tags) {
            for (int i = 0; i < tags.length; i++) {
                if (tags[i] == null) {
                    throw new IllegalArgumentException("Tags must not be null.");
                }
            }
            return tags;
        }

        private static final class TagIs extends EventFilterExpression {

            private final Class<?>[] tags;

            TagIs(Class<?>... tags) {
                this.tags = checkTags(tags);
            }

            @Override
            void collectReferencedTags(Set<Class<?>> collectTags) {
                for (Class<?> tag : tags) {
                    collectTags.add(tag);
                }
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                Class<?>[] filterTags = this.tags;
                for (int i = 0; i < filterTags.length; i++) {
                    Class<?> tag = filterTags[i];
                    if (InstrumentationHandler.hasTagImpl(providedTags, instrumentedNode, tag)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection) {
                for (Class<?> tag : tags) {
                    if (providedTags.contains(tag)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 4;
            }

            @Override
            public String toString() {
                return String.format("tag is one of %s", Arrays.toString(tags));
            }
        }

        private static final class SourceSectionEquals extends EventFilterExpression {

            private final SourceSection[] sourceSections;

            SourceSectionEquals(SourceSection... sourceSection) {
                this.sourceSections = sourceSection;
                // clear tags
                for (int i = 0; i < sourceSection.length; i++) {
                    sourceSections[i] = sourceSection[i];
                }
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection s) {
                for (SourceSection compareSection : sourceSections) {
                    if (s.equals(compareSection)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection) {
                if (rootSection == null) {
                    return true;
                }
                Source rootSource = rootSection.getSource();
                if (rootSource != null) {
                    for (SourceSection compareSection : sourceSections) {
                        if (rootSource.equals(compareSection.getSource())) {
                            return true;
                        }
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 6;
            }

            @Override
            public String toString() {
                return String.format("source-section equals one-of %s", Arrays.toString(sourceSections));
            }

        }

        private static final class RootSourceSectionEquals extends EventFilterExpression {

            private final SourceSection[] sourceSections;

            RootSourceSectionEquals(SourceSection... sourceSection) {
                this.sourceSections = sourceSection;
                // clear tags
                for (int i = 0; i < sourceSection.length; i++) {
                    sourceSections[i] = sourceSection[i];
                }
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection s) {
                return true;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection) {
                if (rootSection == null) {
                    return false;
                }

                for (SourceSection compareSection : sourceSections) {
                    if (rootSection.equals(compareSection)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 6;
            }

            @Override
            public String toString() {
                return String.format("source-section equals one-of %s", Arrays.toString(sourceSections));
            }

        }

        private static final class IndexIn extends EventFilterExpression {

            private final IndexRange[] ranges;

            IndexIn(IndexRange[] ranges) {
                this.ranges = ranges;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSourceSection) {
                if (rootSourceSection == null) {
                    return true;
                }
                return isIncluded(null, null, rootSourceSection);
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                if (!sourceSection.isAvailable()) {
                    return false;
                }
                int otherStart = sourceSection.getCharIndex();
                int otherEnd = otherStart + sourceSection.getCharLength();
                for (IndexRange indexRange : ranges) {
                    if (indexRange.contains(otherStart, otherEnd)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 8;
            }

            @Override
            public String toString() {
                StringBuilder builder = new StringBuilder("(index-between ");
                appendRanges(builder, ranges);
                builder.append(")");
                return builder.toString();
            }
        }

        private static final class LineStartsIn extends EventFilterExpression {

            private final IndexRange[] ranges;

            LineStartsIn(IndexRange[] ranges) {
                this.ranges = ranges;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection) {
                if (rootSection == null) {
                    return true;
                }
                if (!rootSection.isAvailable()) {
                    return false;
                }
                return LineIn.isLineIn(rootSection, ranges);
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                if (!sourceSection.isAvailable()) {
                    return false;
                }
                int otherStart = sourceSection.getStartLine();
                for (IndexRange indexRange : ranges) {
                    if (indexRange.contains(otherStart, otherStart)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 10;
            }

            @Override
            public String toString() {
                StringBuilder builder = new StringBuilder("(line-starts-between ");
                appendRanges(builder, ranges);
                builder.append(")");
                return builder.toString();
            }
        }

        private static final class LineEndsIn extends EventFilterExpression {

            private final IndexRange[] ranges;

            LineEndsIn(IndexRange[] ranges) {
                this.ranges = ranges;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection) {
                if (rootSection == null) {
                    return true;
                }
                if (!rootSection.isAvailable()) {
                    return false;
                }
                return LineIn.isLineIn(rootSection, ranges);
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                int otherStart = sourceSection.getStartLine();
                int otherEnd;
                if (sourceSection.getSource() == null) {
                    otherEnd = otherStart;
                } else {
                    otherEnd = sourceSection.getEndLine();
                }
                for (IndexRange indexRange : ranges) {
                    if (indexRange.contains(otherEnd, otherEnd)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 10;
            }

            @Override
            public String toString() {
                StringBuilder builder = new StringBuilder("(line-ends-between ");
                appendRanges(builder, ranges);
                builder.append(")");
                return builder.toString();
            }
        }

        private static final class LineIn extends EventFilterExpression {

            private final IndexRange[] ranges;

            LineIn(IndexRange[] ranges) {
                this.ranges = ranges;
            }

            @Override
            boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSourceSection) {
                if (rootSourceSection == null) {
                    return true;
                }
                if (!rootSourceSection.isAvailable()) {
                    return false;
                }
                return isIncluded(null, null, rootSourceSection);
            }

            @Override
            boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
                return isLineIn(sourceSection, ranges);
            }

            static boolean isLineIn(SourceSection sourceSection, IndexRange[] ranges) {
                if (!sourceSection.isAvailable()) {
                    return false;
                }
                int otherStart = sourceSection.getStartLine();
                int otherEnd;
                if (sourceSection.getSource() == null) {
                    otherEnd = otherStart;
                } else {
                    otherEnd = sourceSection.getEndLine();
                }
                for (IndexRange indexRange : ranges) {
                    if (indexRange.contains(otherStart, otherEnd)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected int getOrder() {
                return 10;
            }

            @Override
            public String toString() {
                StringBuilder builder = new StringBuilder("(line-between ");
                appendRanges(builder, ranges);
                builder.append(")");
                return builder.toString();
            }
        }

    }

    private static final class Not extends EventFilterExpression {

        private final EventFilterExpression delegate;

        Not(EventFilterExpression delegate) {
            this.delegate = delegate;
        }

        @Override
        boolean isSourceOnly() {
            return delegate.isSourceOnly();
        }

        @Override
        boolean isSourceIncluded(Source source) {
            return !delegate.isSourceIncluded(source);
        }

        @Override
        void collectReferencedTags(Set<Class<?>> collectTags) {
            delegate.collectReferencedTags(collectTags);
        }

        @Override
        boolean isRootIncluded(Set<Class<?>> providedTags, SourceSection rootSection) {
            return true;
        }

        @Override
        boolean isIncluded(Set<Class<?>> providedTags, Node instrumentedNode, SourceSection sourceSection) {
            return !delegate.isIncluded(providedTags, instrumentedNode, sourceSection);
        }

        @Override
        protected int getOrder() {
            return delegate.getOrder();
        }

        @Override
        public String toString() {
            return "not(" + delegate.toString() + ")";
        }

    }

}
