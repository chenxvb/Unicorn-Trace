# Unicorn ARM64 IDA Trace

[简体中文](./README_zh.md)

![alt text](imgs/1.gif)

This project provides a lightweight Unicorn engine-based ARM64 dynamic tracing emulation tool that can run as an IDA Pro plugin or standalone. The tool integrates tightly with IDA to ensure execution consistency and avoid errors. It provides reliable simulation reproduction capabilities and generates beautiful Tenet logs for debugging and analysis. Key features include dynamic code simulation, memory dumping, register state tracking, and instruction-level logging.

The tool doesn't require full memory dumps, instead dynamically dumping memory on demand during execution, making it highly efficient. Process verification ensures the entire acquisition process is complete and error-free. As a trace tool, it's particularly useful for VM analysis with good applicability and speed. Performance may be affected when dealing with numerous external function calls, which may be optimized in the future.

## Key Features

- **IDA Integration Plugin** (`dyn_trace_ida.py`)
  - Configure simulation parameters via GUI (end address, SO name, TPIDR value, etc.)
  - Automatically dump memory segments and register states
  - Support Tenet-compatible trace logs
  - Error handling (memory access exceptions, range checks, etc.)

- **Standalone Emulator** (`local_emu.py`)
  - Load memory maps and register states from files
  - Custom simulation ranges
  - Generate detailed execution logs (`uc.log` and `tenet.log`)
  - Skip external function calls automatically
  - Merge trace logs from multiple execution segments
  - Support for continuous execution across memory dumps
  - Backward slicing for Tenet logs (`trace_slice_tenet.py`)

- **Single Script Mode** (`single_script/dynamic_dump.py`)
  - Direct execution in IDA without library dependencies
  - Lightweight alternative to the full plugin

## File Structure

```
.
├── dyn_trace_ida.py              # IDA plugin version
├── local_emu.py              # Standalone emulator
├── unicorn_trace/                # Emulator core
│   └── unicorn_class.py          # ARM64 emulator base class
│   └── trace_slicer.py           # Tenet backward slicer
├── single_script/                # Utility scripts
│   ├── dynamic_dump.py           # IDA single-script version
│   └── dump_single.py            # Single dump script (not provided)
├── imgs/                         # Screenshots and GIFs
│   ├── 1.gif
│   ├── 2.gif
│   └── 3.gif
├── example.py                    # Example for emulator 
├── trace_slice_tenet.py          # Backward slicing CLI entry
├── README.md                     # English documentation
└── README_zh.md                  # Chinese documentation
```

## Installation & Usage

### Dependencies
```bash
pip install unicorn capstone
```

### IDA Installation
Place `dyn_trace_ida.py` and the `unicorn_trace` folder in IDA's `plugins` directory

### Single Script Mode (Optional)
Use `single_script/dynamic_dump.py` directly in IDA debugging without library files

### Feature 1: Dynamic Dump / Automated Debugging
Run to specified location in IDA, write the target run address, and it will automatically run and record the trace to the end address

#### IDA Plugin Usage
1. Open configuration window with `Ctrl-Alt-U` in IDA
2. Set parameters:
   - End address (relative offset)
   - SO name (optional, required for Tenet)
   - TPIDR value (optional, required if errors occur)
   - Output path (optional, default local)
   - Enable Tenet logging (optional, not recommended as it affects efficiency; suggest offline updates)
3. Click confirm to start simulation

#### IDA Script Usage
If plugin is installed, use `dyn_trace_ida.py` directly. Otherwise use `dynamic_dump.py` from single_script.

Fill required parameters in main function (same as above)

### Feature 2: Standalone Emulator Usage

Run a single dump section.

![alt text](imgs/2.gif)

#### Using `run_once` function (recommended):
```python
from local_emu import run_once

if __name__ == "__main__":
    result = run_once(
        dump_path="./dumps",
        so_path="/path/to/your.so",
        end_addr_relative=0x000000
    )
```

#### Using the emulator class directly:
```python
from unicorn_trace import SelfRunArm64Emulator

# Initialize emulator
emulator = SelfRunArm64Emulator()
emulator.setup_from_files("libtarget.so", "./dumps")

# Run simulation
result = emulator.custom_main_trace(
    so_name="libtarget.so",
    end_addr=0x123456,
    tenet_log_path="./trace.log",
    user_log_path="./sim.log",
    load_dumps_path="./dumps"
)
```

### Feature 3: Simulate The Whole Process
When dealing with code that contains multiple external function calls, the plugin creates separate dump folders for each execution segment. The `run_all_continuous` function in `local_emu.py` allows you to execute all these segments in order, skipping external calls and merging the trace logs.

#### Usage Example:

```python
# In local_emu.py or your own script
from local_emu import run_all_continuous

# Execute all dump folders in chronological order
success = run_all_continuous(
    dump_path="./tmp",
    so_path="/path/to/your.so",
    end_addr_relative=end_addr
)

if success:
    print("Continuous execution completed successfully!")
else:
    print("Continuous execution failed or incomplete.")
```

#### How it works:
1. **Sort dump folders**: Automatically sorts `dump_<timestamp>` folders by timestamp (oldest first)
2. **Continuous execution**: Executes each dump folder in order, starting from the first
3. **External call skipping**: When encountering external function calls (result_code == 1), automatically continues with the next dump folder
4. **Trace merging**: Combines all execution logs into continuous `continuous_sim.log` and `continuous_tenet.log` files
5. **State preservation**: Maintains register state across execution segments (when supported by the emulator)

#### Benefits:
- **Seamless analysis**: Get a continuous trace even when code calls external libraries
- **Time-ordered execution**: Ensures execution follows the actual temporal sequence
- **Automated workflow**: No need to manually run each dump folder separately
- **Consolidated logs**: All trace data in one place for easier analysis

See `example.py`

### Feature 4: Backward Slicing For Tenet Logs (New)

This feature follows the same idea as `trace-slice`: keep only lines that contribute to a target value.

#### Usage

```bash
python3 trace_slice_tenet.py <tenet.log|sim.log> \
  --from reg:x0@last \
  --from mem:0x7752948558@last \
  --dump-dir <dump_dir> \
  -o sliced_tenet.log
```

#### Parameters

- `--from`: slice root (repeatable)
  - `reg:x0@last`: start from the last definition of `x0`
  - `reg:x8@12000`: start from the nearest definition of `x8` at/before line 12000 (1-based)
  - `mem:0x7752948558@last`: start from the last write to this memory byte
  - `mem:0x7752948558@12000`: start from nearest write at/before line 12000
- `--dump-dir`: dump folder with `segment_*.bin`, used to decode instruction-level register read/write dependencies (recommended)
- `--state-trace`: when input is `sim.log`, provide paired `tenet.log` as state source (if omitted, tries sibling `tenet.log` automatically)
- `--keep-load-addr-deps`: by default, slicer prunes register address deps on load lines (`mr=`) and keeps value deps; add this flag to disable pruning
- `-o/--output`: output file path; if omitted, print to stdout

#### Notes

- Works with `tenet.log`, `continuous_tenet.log`, `sim.log`, and `continuous_sim.log`
- If `--dump-dir` is omitted, slicing still works but register dependency precision is lower (memory dependency still works)
- Performance optimization: if all `--from` roots use `@LINE` (not `@last`), slicer scans only up to the max target line, which greatly reduces memory/time on huge traces

## Example Workflow
Also see [Kanxue Article](https://bbs.kanxue.com/thread-289135.htm)

1. **Dynamic Execution, Memory Dump, Save State**:
Use plugin or script to run to end position

2. **Analyze Trace, Generate Tenet Log**:
Use `local_emu.py` to generate tenet.log and combine all logs

3. **Log Analysis, Offline Simulation**:

![alt text](imgs/3.gif)

## Notes

1. Memory region dumping affects efficiency - larger `DUMP_SINGLE_SEG_SIZE` is slower, smaller may cause errors
2. Exception handling support:
   - Memory access errors (UC_ERR_READ_UNMAPPED)
   - Range violations (Code Run out of range)
   - AUTIASP instruction exceptions
   - B4 register handling
   - UNICORN runtime comparison with IDA
3. Each run is independent - if an error occurs mid-run, existing dump folders are unaffected. Just delete the latest error dump file and rerun after fixing the issue
4. Single round external call limit is 50 (shows `restart` when exceeded). Modify `ROUND_MAX` in code to change

## Error Handling

Common error codes:
- Missing `TPIDR`: Need PC value near error (or check log assembly), manually debug to `mrs xxx` location to get `TPIDR` register value. This occurs because IDA can't retrieve it, though it remains constant throughout execution
- IDA breakpoints causing errors: Disable all IDA breakpoints before running to avoid errors during comparison and call skipping
- IDA errors: IDA errors pause execution - just restart

## API Reference

### Main Functions

#### `run_once(dump_path, so_path, end_addr_relative, tdpr=None)`
Execute a single dump folder.

**Parameters:**
- `dump_path`: Path to the dump folder
- `so_path`: Path to the shared object file
- `end_addr_relative`: Target address relative to base
- `tdpr`: Optional TPIDR register value

**Returns:**
- Result code (114514 for success, other codes for errors)

#### `run_all_continuous(dump_path, so_path, end_addr_relative, tdpr=None)`
Execute multiple dump folders continuously.

**Parameters:**
- `dump_path`: Path containing dump folders
- `so_path`: Path to the shared object file
- `end_addr_relative`: Target address relative to base
- `tdpr`: Optional TPIDR register value

**Returns:**
- `True` if execution reached target address, `False` otherwise

#### `main(endaddr_relative, so_path, tpidr_value_input=None, load_path=".", save_path=".")`
Legacy main function for single execution.

### Classes

#### `SelfRunArm64Emulator`
Main emulator class for standalone execution.

**Key methods:**
- `setup_from_files(so_path, load_path)`: Initialize from dump files
- `custom_main_trace(so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps")`: Execute simulation

#### `IDAArm64Emulator`
IDA-integrated emulator class (used by plugin).

## Contribution

Welcome to submit Issues or Pull Requests. Please ensure:
- Follow existing code style
- Add necessary unit tests
- Update relevant documentation

## TODO

### Completed
- ✓ **Continuous execution**: Added `run_all_continuous` function in `local_emu.py` to execute multiple dump folders in order, skip external calls, and merge trace logs
- ✓ **Improve efficiency**: Continue execution after mid-process memory dumps instead of restarting

### In Progress / Future Improvements
- Multi-architecture support
- Better state preservation across execution segments
- Enhanced external call detection and handling
- Performance optimization for large memory dumps
- GUI interface for continuous execution configuration

## Reference

Tenet IDA 9.0: https://github.com/jiqiu2022/Tenet-IDA9.0

Tenet: https://github.com/gaasedelen/tenet

Unicorn Engine: https://github.com/unicorn-engine/unicorn

Capstone Engine: https://github.com/capstone-engine/capstone
