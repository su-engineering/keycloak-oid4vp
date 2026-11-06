/*
 * Copyright 2026 su-engineering
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.suengineering.keycloak.oid4vp.util;

/**
 * Checks untrusted CBOR before it reaches the recursive decoder: nesting depth, truncation and
 * lengths larger than the input. A few kilobytes of nested arrays would otherwise overflow the
 * stack, and a {@link StackOverflowError} escapes every {@code catch (Exception)}.
 *
 * <p>The scan is iterative and reads only item heads; it does not interpret values.
 */
public final class CborLimits {

    /** Deeper than any mdoc, COSE or status list structure needs. */
    public static final int MAX_DEPTH = 32;

    private CborLimits() {}

    public static void check(byte[] cbor) {
        check(cbor, MAX_DEPTH);
    }

    static void check(byte[] cbor, int maxDepth) {
        if (cbor == null || cbor.length == 0) throw new IllegalStateException("Empty CBOR");
        long[] remaining = new long[maxDepth + 2];
        int depth = 0;
        remaining[0] = 1; // one top-level item
        int pos = 0;
        while (true) {
            while (depth >= 0 && remaining[depth] == 0) depth--;
            if (depth < 0) return;
            if (pos >= cbor.length) throw new IllegalStateException("Truncated CBOR");
            int initial = cbor[pos] & 0xff;
            if (initial == 0xff) { // break
                if (remaining[depth] != -1) throw new IllegalStateException("Unexpected CBOR break");
                pos++;
                depth--;
                continue;
            }
            if (remaining[depth] > 0) remaining[depth]--;
            int major = initial >>> 5;
            int info = initial & 0x1f;
            pos++;
            long argument;
            if (info < 24) {
                argument = info;
            } else if (info <= 27) {
                int size = 1 << (info - 24);
                if (pos + size > cbor.length) throw new IllegalStateException("Truncated CBOR");
                argument = 0;
                for (int i = 0; i < size; i++) argument = (argument << 8) | (cbor[pos + i] & 0xff);
                pos += size;
            } else if (info == 31) {
                argument = -1;
            } else {
                throw new IllegalStateException("Reserved CBOR additional information");
            }
            switch (major) {
                case 0, 1 -> {
                    if (argument < 0) throw new IllegalStateException("Indefinite CBOR integer");
                }
                case 2, 3 -> {
                    if (argument == -1) {
                        depth = push(remaining, depth, -1, maxDepth); // chunks until break
                    } else {
                        if (argument < 0 || argument > cbor.length - pos) {
                            throw new IllegalStateException("CBOR string longer than input");
                        }
                        pos += (int) argument;
                    }
                }
                case 4, 5 -> {
                    if (argument == -1) {
                        depth = push(remaining, depth, -1, maxDepth);
                    } else {
                        long items = major == 5 ? argument * 2 : argument;
                        if (argument < 0 || items > cbor.length - pos || items < 0) {
                            throw new IllegalStateException("CBOR container larger than input");
                        }
                        if (items > 0) depth = push(remaining, depth, items, maxDepth);
                    }
                }
                case 6 -> {
                    if (argument < 0) throw new IllegalStateException("Indefinite CBOR tag");
                    depth = push(remaining, depth, 1, maxDepth);
                }
                default -> { // 7: simple values and floats, no content beyond the head
                    if (argument == -1) throw new IllegalStateException("Unexpected CBOR break");
                }
            }
        }
    }

    private static int push(long[] remaining, int depth, long items, int maxDepth) {
        if (depth + 1 > maxDepth) throw new IllegalStateException("CBOR nested deeper than " + maxDepth);
        remaining[depth + 1] = items;
        return depth + 1;
    }
}
