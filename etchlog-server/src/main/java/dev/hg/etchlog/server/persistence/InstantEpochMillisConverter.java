package dev.hg.etchlog.server.persistence;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.time.Instant;

/**
 * Persists every {@link Instant} attribute as epoch milliseconds in a numeric column.
 *
 * <p>Applied automatically to all {@code Instant} fields ({@code autoApply = true}). This keeps
 * timestamp storage identical and unambiguous across both backends — {@code BIGINT} on PostgreSQL,
 * {@code INTEGER} on SQLite — and, critically, makes Hibernate bind/read the value via {@code
 * setLong}/{@code getLong} rather than {@code get/setTimestamp}. The latter is what breaks on the
 * embedded SQLite profile: the community dialect writes an Instant as epoch-millis text, but the
 * xerial driver's {@code getTimestamp} tries to parse it as a {@code yyyy-MM-dd HH:mm:ss.SSS}
 * string and throws, so any cross-session read fails. Epoch-millis longs sidestep date parsing
 * entirely.
 *
 * <p>The STH's signed timestamp is already epoch milliseconds on the wire (see {@code
 * SthEncoding}), so this storage form matches the cryptographic representation exactly.
 */
@Converter(autoApply = true)
public class InstantEpochMillisConverter implements AttributeConverter<Instant, Long> {

    @Override
    public Long convertToDatabaseColumn(Instant attribute) {
        return attribute == null ? null : attribute.toEpochMilli();
    }

    @Override
    public Instant convertToEntityAttribute(Long dbData) {
        return dbData == null ? null : Instant.ofEpochMilli(dbData);
    }
}
