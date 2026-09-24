# Synthetic Cerberus debug logs (emulators only)

The core Cerberus responder defaults to `debug_log=b""`. Supplying explicit
`debug_log` bytes preserves the existing behavior. Set
`synthetic_debug_log=True` on a **mock endpoint** to generate synthetic debug
records instead; this opt-in takes precedence over explicit `debug_log` bytes.
Do not enable this setting for physical or production hardware.

```python
CerberusResponderProfile(
    synthetic_debug_log=True,
    synthetic_debug_log_seed=42,  # optional; independent RNG per endpoint
    synthetic_debug_log_min_size=32768,
    synthetic_debug_log_max_size=65536,
)
```

Each `GET_LOG_INFO` generates a fresh DEBUG snapshot, chooses its total size
uniformly from the configured inclusive range, and reports the exact resulting
length. A newly created endpoint also has an initial snapshot, so a direct
`READ_LOG` before the first `GET_LOG_INFO` reads synthetic data. The default
range is 32-64 KiB; bounds must satisfy
`28 <= min_size <= max_size <= 65536`. The entire immutable byte snapshot is
retained per endpoint until the next `GET_LOG_INFO`. `READ_LOG` slices it at
the requested offset (at most 4091 bytes per reply, or a smaller configured
`max_log_chunk`); offsets past the end return empty bytes. `CLEAR_LOG` discards
the current snapshot immediately, including unread chunks. The next
`GET_LOG_INFO` generates a new one. Other log types retain their existing
behavior.

Records use the public Cerberus Utility's packed `0xCB` debug entry layout.
The generated messages and arguments are synthetic and do not represent
hardware events or any Microsoft-specific decoder extension. Each whole
variable-length record is:

| Offset | Size | Synthetic meaning |
| --- | ---: | --- |
| 0 | 1 | Debug entry magic (`0xCB`) |
| 1 | 2 | Total record length, little-endian (`28..96`) |
| 3 | 4 | Entry ID, little-endian (starts at zero per snapshot) |
| 7 | 2 | Format identifier, little-endian (`0`) |
| 9 | 1 | Severity (`0..2`) |
| 10 | 1 | Generic MCTP component (`13`) |
| 11 | 1 | MCTP message index (`0..3`) |
| 12 | 4 | Synthetic argument 1, little-endian |
| 16 | 4 | Synthetic argument 2, little-endian |
| 20 | 8 | Synthetic elapsed time in milliseconds, little-endian |
| 28 | variable | PRNG-generated extension (no captured device data) |

The generator fits complete records into the selected size, without exceeding
64 KiB or padding with partial records. A fixed seed reproduces a given
endpoint's sequence of snapshots; each endpoint owns its own RNG, so requests
to one endpoint do not advance another's stream. The record layout is defined in the public
[Cerberus Utility decoder](https://github.com/Azure/Cerberus-Utility/blob/503e6438f32c6edf5a43f813ae094a85d58a8e3d/cerberus_utility_commands_internal.h#L812-L850);
its message meanings and optional extensions are not intended to reproduce
production device logs. The decoder advances by the total record length.
