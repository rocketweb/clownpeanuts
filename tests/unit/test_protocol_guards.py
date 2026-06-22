import socket
import struct

from clownpeanuts.services.database.memcached_emulator import Emulator as MemcachedEmulator
from clownpeanuts.services.database.mongo_emulator import Emulator as MongoEmulator
from clownpeanuts.services.database.mysql_emulator import Emulator as MySQLEmulator
from clownpeanuts.services.database.postgres_emulator import Emulator as PostgresEmulator
from clownpeanuts.services.database.redis_emulator import Emulator as RedisEmulator
from clownpeanuts.services.http.emulator import Emulator as HttpEmulator
from clownpeanuts.services.ssh.emulator import Emulator as SSHEmulator


def test_http_content_length_is_bounded() -> None:
    assert HttpEmulator._bounded_content_length("2147483647", 65_536) == 65_536
    assert HttpEmulator._bounded_content_length("-1", 65_536) == 0
    assert HttpEmulator._bounded_content_length("invalid", 65_536) == 0


def test_http_auth_failed_view_escapes_user_input() -> None:
    html_payload = HttpEmulator._auth_failed_view(
        username="<script>alert('x')</script>",
        route="/admin?next='><script>evil()</script>",
    )
    assert "<script>alert('x')</script>" not in html_payload
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in html_payload
    assert "&lt;script&gt;evil()&lt;/script&gt;" in html_payload


def test_http_narrative_focus_label_escapes_html() -> None:
    narrative = {
        "focus": {
            "service": {
                "label": "<img src=x onerror=alert(1)>",
            }
        }
    }
    label = HttpEmulator._narrative_focus_label(narrative, kind="service", default="ops-portal")
    assert label == "&lt;img src=x onerror=alert(1)&gt;"


def test_redis_rejects_oversized_resp_array_and_bulk_length() -> None:
    emulator = RedisEmulator()

    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        writer.sendall(b"*999999\r\n")
        writer.shutdown(socket.SHUT_WR)
        assert emulator._read_command(reader) is None
    finally:
        reader.close()
        writer.close()

    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        writer.sendall(b"*1\r\n$999999\r\n")
        writer.shutdown(socket.SHUT_WR)
        assert emulator._read_command(reader) is None
    finally:
        reader.close()
        writer.close()


def test_redis_enforces_total_store_limit() -> None:
    emulator = RedisEmulator()
    emulator._MAX_TOTAL_STORE_BYTES = 9

    first, _ = emulator._execute_command(
        command=["SET", "k1", "12345"],
        session_id="redis-limit",
        source_ip="203.0.113.9",
        source_port=6379,
    )
    assert first == b"+OK\r\n"

    second, _ = emulator._execute_command(
        command=["SET", "k2", "67890"],
        session_id="redis-limit",
        source_ip="203.0.113.9",
        source_port=6379,
    )
    assert second.startswith(b"-OOM")


def test_mongo_rejects_oversized_frame_before_body_read() -> None:
    emulator = MongoEmulator()
    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        oversized = struct.pack("<iiii", (8 * 1024 * 1024) + 1, 7, 0, 2013)
        writer.sendall(oversized)
        writer.shutdown(socket.SHUT_WR)
        assert emulator._read_frame(reader) is None
    finally:
        reader.close()
        writer.close()


def test_mysql_rejects_oversized_packet_before_body_read() -> None:
    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        oversized = MySQLEmulator._MAX_PACKET_PAYLOAD_BYTES + 1
        writer.sendall(oversized.to_bytes(3, "little") + b"\x00")
        writer.shutdown(socket.SHUT_WR)
        assert MySQLEmulator._read_packet(reader) is None
    finally:
        reader.close()
        writer.close()


def test_postgres_rejects_oversized_startup_and_message_lengths() -> None:
    emulator = PostgresEmulator()

    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        writer.sendall(struct.pack("!I", emulator._MAX_MESSAGE_SIZE_BYTES + 1))
        writer.shutdown(socket.SHUT_WR)
        assert emulator._read_startup_packet(reader) is None
    finally:
        reader.close()
        writer.close()

    reader, writer = socket.socketpair()
    try:
        reader.settimeout(1.0)
        writer.sendall(b"Q" + struct.pack("!I", emulator._MAX_MESSAGE_SIZE_BYTES + 1))
        writer.shutdown(socket.SHUT_WR)
        assert emulator._read_message(reader) is None
    finally:
        reader.close()
        writer.close()


def test_ssh_shell_state_cache_evicts_oldest_entry_when_capacity_reached() -> None:
    emulator = SSHEmulator()
    emulator._MAX_SHELL_STATES = 2
    emulator._session_shell_state(session_id="s1", username="root")
    emulator._session_shell_state(session_id="s2", username="root")
    emulator._session_shell_state(session_id="s1", username="root")
    emulator._session_shell_state(session_id="s3", username="root")
    assert set(emulator._shell_state.keys()) == {"s1", "s3"}


def test_mysql_recv_exact_aborts_slow_trickle() -> None:
    # A 1-byte-at-a-time trickle must hit the per-packet wall-clock deadline
    # instead of holding the connection slot indefinitely.
    reader, writer = socket.socketpair()
    try:
        reader.settimeout(5.0)
        MySQLEmulator._MAX_PACKET_READ_SECONDS = 0.3
        writer.sendall(b"\x01")  # one byte of a 4-byte read, then stall
        assert MySQLEmulator._recv_exact(reader, 4) is None
    finally:
        MySQLEmulator._MAX_PACKET_READ_SECONDS = 30.0
        reader.close()
        writer.close()


def test_ssh_recvline_aborts_slow_trickle() -> None:
    emulator = SSHEmulator()
    emulator._max_line_read_seconds = 0.3
    reader, writer = socket.socketpair()
    try:
        reader.settimeout(5.0)
        writer.sendall(b"r")  # one byte, no newline, then stall
        assert emulator._recvline(reader) is None
    finally:
        reader.close()
        writer.close()


def test_http_handler_sets_idle_timeout_and_read_deadline() -> None:
    emulator = HttpEmulator()
    emulator._connection_idle_timeout_seconds = 7.0
    emulator._request_read_deadline_seconds = 11.0
    handler_cls = emulator._build_handler()
    # The idle timeout is applied to the connection socket via the class attr.
    assert handler_cls.timeout == 7.0
    assert emulator._request_read_deadline_seconds == 11.0


def _bson_cstring(name: str) -> bytes:
    return name.encode("ascii") + b"\x00"


def _bson_nested_doc(depth: int) -> bytes:
    # Build a BSON document nested `depth` levels deep: {"a": {"a": {...}}}.
    doc = struct.pack("<i", 5) + b"\x00"  # innermost empty document (len=5)
    for _ in range(depth):
        body = b"\x03" + _bson_cstring("a") + doc  # element type 0x03 (embedded doc)
        doc = struct.pack("<i", len(body) + 5) + body + b"\x00"
    return doc


def test_mongo_decoder_bounds_nesting_depth() -> None:
    emulator = MongoEmulator()
    # Far deeper than Python's recursion limit; must not raise, must not recurse
    # past the cap (returns an empty doc at the boundary).
    payload = _bson_nested_doc(5000)
    result, _ = emulator._decode_document(payload)
    assert isinstance(result, dict)


def test_mongo_decoder_tolerates_non_numeric_array_keys() -> None:
    emulator = MongoEmulator()
    # A BSON array (0x04) whose element key is non-numeric must not raise.
    inner_body = b"\x10" + _bson_cstring("x") + struct.pack("<i", 7)  # int32 element keyed "x"
    inner = struct.pack("<i", len(inner_body) + 5) + inner_body + b"\x00"
    value, _ = emulator._decode_value(inner, 0, 0x04)
    assert value == [7]


def test_redis_store_cap_counts_key_name_bytes() -> None:
    emulator = RedisEmulator()
    emulator._MAX_TOTAL_STORE_BYTES = 20
    # Empty value, but a long key name must still consume budget.
    long_key = "k" * 15
    first, _ = emulator._execute_command(
        command=["SET", long_key, ""],
        session_id="redis-keybytes",
        source_ip="203.0.113.9",
        source_port=6379,
    )
    assert first == b"+OK\r\n"
    second, _ = emulator._execute_command(
        command=["SET", "k" * 15 + "x", ""],  # another 16-byte key name
        session_id="redis-keybytes",
        source_ip="203.0.113.9",
        source_port=6379,
    )
    assert second.startswith(b"-OOM")


def test_redis_store_enforces_key_count_cap() -> None:
    emulator = RedisEmulator()
    emulator._MAX_STORE_KEYS = 3
    for i in range(3):
        reply, _ = emulator._execute_command(
            command=["SET", f"k{i}", "v"],
            session_id="redis-keycap",
            source_ip="203.0.113.9",
            source_port=6379,
        )
        assert reply == b"+OK\r\n"
    over, _ = emulator._execute_command(
        command=["SET", "k4", "v"],
        session_id="redis-keycap",
        source_ip="203.0.113.9",
        source_port=6379,
    )
    assert over.startswith(b"-OOM")
    # Overwriting an existing key is still allowed at the cap.
    overwrite, _ = emulator._execute_command(
        command=["SET", "k0", "v2"],
        session_id="redis-keycap",
        source_ip="203.0.113.9",
        source_port=6379,
    )
    assert overwrite == b"+OK\r\n"


def test_memcached_can_store_value_counts_key_bytes_and_key_cap() -> None:
    emulator = MemcachedEmulator()
    emulator._MAX_TOTAL_STORE_BYTES = 20
    # Long key name with empty value must count toward the budget.
    emulator._store["k" * 15] = b""
    assert emulator._can_store_value_locked("k" * 15 + "y", b"") is False

    emulator2 = MemcachedEmulator()
    emulator2._MAX_STORE_KEYS = 2
    emulator2._store["a"] = b"v"
    emulator2._store["b"] = b"v"
    assert emulator2._can_store_value_locked("c", b"v") is False  # new key over cap
    assert emulator2._can_store_value_locked("a", b"v2") is True  # overwrite allowed
