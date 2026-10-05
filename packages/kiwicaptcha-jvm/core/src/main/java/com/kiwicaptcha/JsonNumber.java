package com.kiwicaptcha;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A decoded json number carried as its raw literal text, so an encode
 * of a decoded token re-emits the exact wire spelling instead of a
 * reformatted float.
 */
public final class JsonNumber {
    /** The raw literal text of the number. */
    public final String raw;

    public JsonNumber(String raw) {
        this.raw = raw;
    }

    /** Parses the literal as a long, or fails for a non-integer. */
    public long longValue() {
        return Long.parseLong(raw);
    }

    /** Parses the literal as an int, or fails outside the int range. */
    public int intValue() {
        return Integer.parseInt(raw);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof JsonNumber other && raw.equals(other.raw);
    }

    @Override
    public int hashCode() {
        return raw.hashCode();
    }

    @Override
    public String toString() {
        return raw;
    }
}
