package dev.hg.etchlog.starter;

/**
 * Internal wire DTO for the append request body sent to the server.
 *
 * <p>Serializes to:
 *
 * <pre>{@code
 * {"leaf_data": "<standard-base64 of payload bytes>"}
 * }</pre>
 *
 * <p>With a snake_case ObjectMapper, the camelCase field {@code leafData} serializes to {@code
 * leaf_data} automatically.
 */
record AppendRequestWire(byte[] leafData) {}
