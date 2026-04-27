# eBPF Multi-Format Payload Decoder

Host-side eBPF pipeline for enforcing per-port payload policy and emitting decoded log payloads for configured traffic.

The current implementation is centered on four configured actions: `decode`, `drop`, `pass`, and `check`. Kernel programs make the packet decision first. Userspace only receives payloads that passed the kernel gates, then performs stream framing, content classification, and strict decoding.

## Current Architecture

- **Loader**: `userspace/loader` loads and pins BPF programs/maps, then programs `config/intercept.yaml` into the shared `port_proto_filter` map.
- **XDP**: `kernel/layer1_xdp` performs early `(port, protocol)` lookup and enforces fast `drop`/`pass` decisions.
- **TC ingress**: `kernel/layer1_tc` applies bounded payload format guards for `check` and `decode`, drops configured mismatches, tracks TCP continuation state, and emits small payload events through the ring buffer.
- **SK_MSG**: `kernel/layer4_transport` handles larger TCP payloads through the shared arena/ringbuf path and applies the same action/format policy model.
- **Decoder**: `userspace/decoder` reads ringbuf events, mmaps the large-payload array, reconstructs TCP frames, classifies content signatures, and decodes JSON, syslog, HTML, or plaintext.

## Configuration

Each entry in `config/intercept.yaml` configures one `(port, protocol)` pair:

```yaml
intercept:
  - port: 443
    protocol: tcp
    format: html
    action: decode
  - port: 8080
    protocol: tcp
    format: json
    action: decode
    inject: "classification:application_log"
  - port: 53
    protocol: udp
    format: plain_text
    action: check
  - port: 514
    protocol: udp
    format: syslog
    action: decode
    inject: "classification:syslog"
```

Supported `protocol` values are `tcp` and `udp`.

Supported `format` values are `json`, `syslog`, `html`, and `plain_text`.

Supported `action` values:

- `decode`: validate the payload against the configured format, send accepted payloads to userspace, frame/classify/decode them, and print decoded events.
- `check`: validate the payload against the configured format in kernel, then pass valid packets without decoder output.
- `drop`: drop matching packets unconditionally.
- `pass`: pass matching packets without capture or decode.

`decode` entries may include optional `inject` metadata. For JSON payloads, `inject: "field:value"` inserts or overwrites the top-level decoded JSON field with a string value. For syslog, HTML, and plaintext payloads, the configured string is emitted as a top-level `inject` field in the decoder output envelope. `inject` is rejected for `drop`, `pass`, and `check`.

For `check` and `decode`, payload/format mismatch is fail-closed at the kernel guard. For example, an ELF, PE, PDF, ZIP, gzip, PNG, or JPEG payload sent to a JSON port should be dropped or suppressed rather than decoded as plaintext.

## Userspace Decoding

The decoder is strict when the kernel provides an expected format. It does not sniff a failed JSON payload and silently downgrade it to plaintext for a configured JSON port.

Current userspace behavior:

- JSON over TCP is newline-framed by default, suitable for JSONL-style logs.
- Syslog over TCP supports octet-counted and newline-delimited frames.
- UDP remains datagram-oriented.
- HTML and plaintext are treated as raw payload frames.
- Built-in content classification rejects obvious binary/file payloads before strict parser decode.
- Emitted events include action/format context and classification metadata when available.

## Build

```bash
make all
```

Useful targeted checks:

```bash
cargo test --manifest-path userspace/decoder/Cargo.toml
cargo check --manifest-path userspace/loader/Cargo.toml
make kernel
cargo build --release --workspace
```

## Run

Preferred path: let the Rust loader initialize the full pipeline when no pinned maps exist. It loads XDP, TC, SockOps, SK_MSG, pins the shared maps, applies the YAML config, and watches the config file for changes.

```bash
sudo ./target/release/ebpf-json-loader --interface ens33 --config config/intercept.yaml
```

Start the decoder in another terminal:

```bash
sudo ./target/release/ebpf-json-decoder
```

The decoder reads `config/intercept.yaml` by default to apply optional `inject` metadata. Use `--config <path>` if the loader is using a different config file.

If the pipeline is already loaded and pinned, starting the loader again only reuses `port_proto_filter` and applies/watches the YAML config:

```bash
sudo ./target/release/ebpf-json-loader --config config/intercept.yaml
```

If you changed BPF map layouts or pinned map definitions, unload first so stale pinned maps are not reused:

```bash
sudo ./scripts/unload_pipeline.sh ens33
sudo ./target/release/ebpf-json-loader --interface ens33 --config config/intercept.yaml
```

`scripts/load_pipeline.sh` is useful for XDP/TC-only debugging, but it does not attach the full SockOps/SK_MSG large-payload path.

## Manual Validation

For the current sample config, JSON on TCP port `8080` expects newline-delimited JSON:

```bash
printf '{"event":"manual-test","ok":true}\n' | nc <host> 8080
```

Wrong content on a typed port should not produce decoded output:

```bash
printf 'MZfake-binary\n' | nc <host> 8080
```

Syslog on UDP port `514` can be checked with:

```bash
printf '<13>Apr 21 13:00:00 host app: hello\n' | nc -u <host> 514
```

When testing from Windows, use a byte-sending PowerShell helper instead of typing payloads interactively, because interactive tools often add buffering or newline behavior that hides framing issues.

## Operational Notes

- Kernel format checks are intentionally bounded heuristics, not full parsers.
- Userspace classification is the deeper validation layer, but it is still signature/shape based and does not use Magika/libmagic yet.
- Ringbuf or arena pressure can drop log events; configured `drop` and format mismatch under `check`/`decode` drop packets.
- TCP framing is best-effort and depends on stable connection metadata from the emitting kernel path.
- Large payload handling is bounded by the configured arena slot size and global decoder caps.

## Documentation

Additional implementation notes live in:

- `docs/ARCHITECTURE.md`
- `docs/DEVELOPER_MANUAL.md`
- `docs/PLAN_CONFIG_EXTENSIONS.md`
- `docs/QA_JSON_DECODER.md`
- `docs/PERFORMANCE_GUIDE.md`
- `obsidian_space/50_CODE_INDEX_CONCISE.md`
- `obsidian_space/62_ACTIONS_IMPLEMENTATION_GUIDE.md`
