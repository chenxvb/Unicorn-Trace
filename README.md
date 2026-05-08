# Unicorn ARM64 Tracer (IDA + Offline)

[简体中文](./README_zh.md)

![IDA plugin demo](imgs/1.gif)

Lightweight ARM64 tracing workflow based on Unicorn.

- `dyn_trace_ida.py`: IDA plugin (interactive dump + trace)
- `local_emu.py`: offline replay / continuous replay
- `single_script/dynamic_dump.py`: single-file fallback script for IDA

## Install

```bash
pip install unicorn capstone
```

Copy to IDA plugin directory:

- `dyn_trace_ida.py`
- `unicorn_trace/`

## IDA Plugin (Current Behavior)

Open with `Ctrl-Alt-U` (`Unicorn ARM64 Tracer`).

The plugin window is a non-modal popup and stays on top.

### Parameters

- `END addr`: hex; **relative to image base by default**
- `TPIDR`: optional
- `Bound start / Bound end`: custom run range
- `Output path`: output directory
- `enable Tenet`: emit tenet logs
- `end addr absolute`: treat END as absolute address

### Important UI Logic

- Auto range is from **current PC executable segment**.
- `Refresh Range` will overwrite `Bound start/end` with current auto range.
- Custom bound is always enabled (no extra toggle).
- A runtime log popup is available (`Show Log` / `Clear Log`) and updates live during execution.

### Input/Output Cache

Per-IDB cache is stored under user IDA directory (`~/.idapro/...`).
It restores last inputs and last output paths when reopening the plugin.

## Usage Paths (Both Require Plugin Installation)

Both paths require `dyn_trace_ida.py` + `unicorn_trace/` in IDA `plugins`.

### Path A: Plugin GUI

1. Press `Ctrl-Alt-U` in IDA.
2. Fill parameters in popup.
3. Click `Run Tracer`.

### Path B: IDA Script

Run inside IDA Python:

```python
# Option 1: execute script file directly in IDA
# File -> Script file... -> select dyn_trace_ida.py

# Option 2: import and call
import dyn_trace_ida
dyn_trace_ida.uni_trace_main(
    endaddr_input=0x1234,          # relative by default
    tpidr_value_input=None,
    enable_tenet=False,
    user_path=".",
    end_addr_absolute=False,
    use_custom_bound=True,
    bound_start=0x100000000,
    bound_end=0x100010000,
)
```

## Output Files

Under `Output path`:

- `uc_combine_<timestamp>.log`
- `dump_<timestamp>/regs.json`
- `dump_<timestamp>/uc.log`
- `dump_<timestamp>/tenet.log` (when Tenet enabled)
- `tenet_combine_<timestamp>.log` (when Tenet enabled)

## Offline Replay

Use `local_emu.py` for replaying dumped data.

![Offline replay demo](imgs/2.gif)

Common entry points:

- `run_once(...)`: replay one dump folder
- `run_all_continuous(...)`: replay multiple `dump_*` folders in time order and merge logs

Quick example:

```python
from local_emu import run_all_continuous

run_all_continuous(
    dump_path="./tmp/report_list",
    debug_switch=True,
)
```

See [`example.py`](./example.py) for a hook-based example.

## Workflow (Visual)

![Workflow demo](imgs/3.gif)

## Notes

- The plugin still relies on `ida_dbg.run_to(...)` in recovery paths; debugger events may switch IDA view/focus.
- Disable unrelated breakpoints when tracing to reduce interference.
- If a run fails midway, previous dump folders remain usable.

## References

- Tenet (official): https://github.com/gaasedelen/tenet
- Tenet-IDA9.0: https://github.com/jiqiu2022/Tenet-IDA9.0

## Repo Layout (Current)

```text
.
├── dyn_trace_ida.py
├── local_emu.py
├── example.py
├── unicorn_trace/
│   ├── __init__.py
│   └── unicorn_class.py
├── single_script/
│   ├── dynamic_dump.py
│   └── dump_single.py
├── README.md
└── README_zh.md
```
