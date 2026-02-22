from __future__ import annotations

import os


# Keep default-config test runs deterministic now that Redis URLs always require
# an explicit credential interpolation value.
os.environ.setdefault("CP_REDIS_PASSWORD", "unit-test-redis-password")
