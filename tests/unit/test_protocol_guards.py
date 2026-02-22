import socket
import struct

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
