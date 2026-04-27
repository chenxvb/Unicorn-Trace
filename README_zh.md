# Unicorn ARM64 IDA 追踪工具

[English](./README.md)

![alt text](imgs/1.gif)

本项目提供了一套轻量级的基于 Unicorn 引擎的 ARM64 动态追踪模拟工具，支持在 IDA Pro 中作为插件运行或独立执行。本工具与 IDA 紧密集成，确保执行过程与 IDA 一致，避免出错；提供可靠的模拟执行再现能力，并生成美观的 Tenet 日志用于调试分析。主要功能包括动态代码模拟、内存转储、寄存器状态追踪和指令级日志记录。

本工具无需全量 dump 内存，只在运行过程中按需动态 dump 内存因此效率和速度都很高，再加上过程检查能确保整个获取过程都是完善无误的。作为 trace 工具，该工具在 vm 分析中相当有用，适用性和速率都很好。但在外部调用非常多且密集的用户函数，效率会受到很大影响，后续可能会针对此进行优化。

## 主要功能

- **IDA 集成插件** (`dyn_trace_ida.py`)
  - 通过 GUI 配置模拟参数（结束地址、SO 名称、TPIDR 值等）
  - 自动转储内存段和寄存器状态
  - 支持 Tenet 兼容的追踪日志
  - 错误处理（内存访问异常、范围检查等）

- **独立模拟器** (`local_emu.py`)
  - 从文件加载内存映射和寄存器状态
  - 自定义模拟范围
  - 生成详细执行日志（`uc.log` 和 `tenet.log`）
  - 自动跳过外部函数调用
  - 合并多个执行片段的追踪日志
  - 支持跨内存转储的连续执行
  - 支持 Tenet 日志反向切片（`trace_slice_tenet.py`）

- **单脚本模式** (`single_script/dynamic_dump.py`)
  - 直接在 IDA 中执行，无需库文件依赖
  - 完整插件的轻量级替代方案

## 文件结构

```
.
├── dyn_trace_ida.py              # IDA 插件版本
├── local_emu.py              # 独立模拟器
├── unicorn_trace/                # 模拟器核心
│   └── unicorn_class.py          # ARM64 模拟器基类
│   └── trace_slicer.py           # Tenet 反向切片器
├── single_script/                # 实用脚本
│   ├── dynamic_dump.py           # IDA 单脚本版本
│   └── dump_single.py            # 单次转储脚本（未提供）
├── imgs/                         # 截图和 GIF
│   ├── 1.gif
│   ├── 2.gif
│   └── 3.gif
├── example.py                    # 离线模拟调用样例 
├── trace_slice_tenet.py          # 反向切片 CLI 入口
├── README.md                     # 英文文档
└── README_zh.md                  # 中文文档
```

## 安装与使用

### 依赖安装
```bash
pip install unicorn capstone
```

### IDA 安装

将 `dyn_trace_ida.py` 和 `unicorn_trace` 文件夹放入 IDA 的 `plugins` 目录

### 单脚本模式（可选）

直接使用 `single_script/dynamic_dump.py` 在 IDA 调试时启用，无需使用库文件

### 功能一：动态 dump / 自动化调试

ida 调试到指定位置后，写入期望的运行地址，会自动运行且记录 trace 到那结束地址

#### IDA 插件使用
1. 在 IDA 中使用 `Ctrl-Alt-U` 打开配置窗口
2. 设置参数：
   - 结束地址（相对偏移）
   - SO 名称 （可选，启用 tenet 需要填）
   - TPIDR 值（可选，遇到报错需要填写）
   - 输出路径 （可选，默认本地）
   - 是否启用 Tenet 日志 （可选，不建议启用，影响效率，建议离线更新）
3. 点击确认开始模拟

#### IDA 脚本使用

已安装插件可以直接使用 `dyn_trace_ida.py` 脚本，如未安装也可以使用上面单脚本 `dynamic_dump.py`

直接在 main 函数里填写所需参数，内容同上

### 功能二：独立模拟器使用

运行单个 dump 片段。

![alt text](imgs/2.gif)

#### 使用 `run_once` 函数（推荐）：
```python
from local_emu import run_once

if __name__ == "__main__":
    result = run_once(
        dump_path="./dumps",
        so_path="/path/to/your.so",
        end_addr_relative=0x000000,
        tdpr=None  # 可选的 TPIDR 值
    )
```

#### 直接使用模拟器类：
```python
from unicorn_trace import SelfRunArm64Emulator

# 初始化模拟器
emulator = SelfRunArm64Emulator()
emulator.setup_from_files("libtarget.so", "./dumps")

# 运行模拟
result = emulator.custom_main_trace(
    so_name="libtarget.so",
    end_addr=0x123456,
    tenet_log_path="./trace.log",
    user_log_path="./sim.log",
    load_dumps_path="./dumps"
)
```

### 功能三：追踪全部流程

当处理包含多个外部函数调用的代码时，插件会为每个执行片段创建单独的 dump 文件夹。`local_emu.py` 中的 `run_all_continuous` 函数允许您按顺序执行所有这些片段，跳过外部调用并合并追踪日志。

你可以直接把它当黑盒用，直接可以模拟执行全部流程

#### 使用示例：

```python
# 在 local_emu.py 或您自己的脚本中
from local_emu import run_all_continuous

# 按时间顺序执行所有 dump 文件夹
success = run_all_continuous(
    dump_path="./tmp",
    so_path="/path/to/your.so",
    end_addr_relative=end_addr
)

if success:
    print("连续执行成功完成！")
else:
    print("连续执行失败或未完成。")
```

#### 工作原理：
1. **排序 dump 文件夹**：自动按时间戳排序 `dump_<timestamp>` 文件夹（从早到晚）
2. **连续执行**：按顺序执行每个 dump 文件夹，从第一个开始
3. **外部调用跳过**：遇到外部函数调用时（result_code == 1），自动继续下一个 dump 文件夹
4. **日志合并**：将所有执行日志合并为连续的 `continuous_sim.log` 和 `continuous_tenet.log` 文件
5. **状态保持**：在执行片段之间保持寄存器状态（当模拟器支持时）

#### 优势：
- **无缝分析**：即使代码调用外部库也能获得连续追踪
- **时间顺序执行**：确保执行遵循实际的时间顺序
- **自动化工作流**：无需手动单独运行每个 dump 文件夹
- **统一日志**：所有追踪数据集中一处，便于分析

可以参考 `example.py` 实现

### 功能四：Tenet 日志反向切片（新增）

该功能参考 `trace-slice` 的思路，将与目标值相关的指令行从海量 `tenet.log` 中自动提取出来。

#### 使用方式

```bash
python3 trace_slice_tenet.py <tenet.log|sim.log> \
  --from reg:x0@last \
  --from mem:0x7752948558@last \
  --dump-dir <dump_目录> \
  -o sliced_tenet.log
```

#### 参数说明

- `--from`：切片起点（可重复）
  - `reg:x0@last`：从寄存器最后一次定义开始
  - `reg:x8@12000`：从第 12000 行（1-based）及之前最近一次 `x8` 定义开始
  - `mem:0x7752948558@last`：从内存字节最后一次写入开始
  - `mem:0x7752948558@12000`：从第 12000 行及之前最近一次写入该地址开始
- `--dump-dir`：包含 `segment_*.bin` 的 dump 文件夹，用于按 PC 反汇编并恢复寄存器读写依赖（建议提供）
- `--state-trace`：当主输入是 `sim.log` 时，提供对应 `tenet.log` 作为寄存器/内存状态源（不填会自动尝试同目录 `tenet.log`）
- `--keep-load-addr-deps`：默认会剪掉加载指令（`mr=`）的地址寄存器依赖，仅保留数据来源；加此参数可关闭剪枝
- `-o/--output`：输出切片日志文件；不填则打印到标准输出

#### 说明

- 输入支持 `tenet.log` / `continuous_tenet.log` / `sim.log` / `continuous_sim.log`
- 不提供 `--dump-dir` 时仍可运行，但寄存器依赖精度会降低（内存依赖仍可追踪）
- 性能优化：当所有 `--from` 都是 `@行号`（不是 `@last`）时，切片器只扫描到最大目标行，内存占用和耗时会显著下降

## 示例工作流

也可以参考[看雪文章](https://bbs.kanxue.com/thread-289135.htm)

1. **动态执行、内存转储、保存现场**：

使用插件或者脚本运行到结束位置

2. **分析 trace，生成 tenet log**：

使用 `local_emu.py` 生成 tenet.log，组合所有 log

3. **日志分析，离线模拟执行**：

![alt text](imgs/3.gif)

## 注意事项

1. 处理特殊寄存器值（如 TPIDR）时需手动配置
2. 内存区域转储关乎效率 `DUMP_SINGLE_SEG_SIZE` 越大越慢，越小越可能出错
3. 异常处理支持：
   - 内存访问错误（UC_ERR_READ_UNMAPPED）
   - 范围越界（Code Run out of range）
   - AUTIASP 指令异常
   - B4 寄存器处理
   - UNICORN 运行中和 IDA 对比检查
4. 单次运行流程都是独立的，因此哪怕中间出错，对于已经生成的 dump 文件夹都是没有影响的。仅需删除最新出错 dump 文件以及处理报错原因后再次运行即可
5. 单大轮外部调用上限为 50，如果超过会显示 `restart` 后停下。如果希望更改长度可以在代码中更改 `ROUND_MAX`

## 错误处理

常见错误代码：
- 缺乏 `TPIDR`：需要报错结果附近 pc 值（或者看 log 汇编），手动调试到 `mrs xxx` 处后获取 `TPIDR` 寄存器的数值。这是因为 ida 无法获取导致的。不过全运行流程中都不会变化
- ida 断点导致出错：最好在运行时手动 disable 所有的 ida 断点，不然在运行对比和跳过调用时可能会出错
- ida 报错：ida 报错会导致运行暂停，再次运行即可

## API 参考

### 主要函数

#### `run_once(dump_path, so_path, end_addr_relative, tdpr=None)`
执行单个 dump 文件夹。

**参数：**
- `dump_path`：dump 文件夹路径
- `so_path`：共享对象文件路径
- `end_addr_relative`：相对于基址的目标地址

**返回值：**
- 结果代码（114514 表示成功，其他代码表示错误）

#### `run_all_continuous(dump_path, so_path, end_addr_relative, tdpr=None)`
连续执行多个 dump 文件夹。

**参数：**
- `dump_path`：包含 dump 文件夹的路径
- `so_path`：共享对象文件路径
- `end_addr_relative`：相对于基址的目标地址

**返回值：**
- 如果执行到达目标地址返回 `True`，否则返回 `False`

#### `main(endaddr_relative, so_path, tpidr_value_input=None, load_path=".", save_path=".")`
传统的单次执行主函数。

### 类

#### `SelfRunArm64Emulator`
用于独立执行的主要模拟器类。

**关键方法：**
- `setup_from_files(so_path, load_path)`：从 dump 文件初始化
- `custom_main_trace(so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps")`：执行模拟

#### `IDAArm64Emulator`
IDA 集成模拟器类（插件使用）。

## 贡献

欢迎提交 Issue 或 Pull Request。请确保：
- 遵循现有代码风格
- 添加必要的单元测试
- 更新相关文档

## TODO

### 已完成
- ✓ **连续执行**：在 `local_emu.py` 中添加了 `run_all_continuous` 函数，可按顺序执行多个 dump 文件夹，跳过外部调用并合并追踪日志
- ✓ **提升效率**：中间 dump mem 后接着后续运行而不是重新开始

### 进行中 / 未来改进
- 多架构适配
- 更好的执行片段间状态保持
- 增强的外部调用检测和处理
- 大型内存转储的性能优化
- 连续执行的 GUI 界面配置

## 参考

Tenet IDA 9.0: https://github.com/jiqiu2022/Tenet-IDA9.0

Tenet: https://github.com/gaasedelen/tenet

Unicorn Engine: https://github.com/unicorn-engine/unicorn

Capstone Engine: https://github.com/capstone-engine/capstone
