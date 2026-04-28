import glob
import json
import re
import os
import time
from unicorn import *
from unicorn.arm64_const import *
from unicorn_trace.unicorn_class import Arm64Emulator  # 导入父类

class SelfRunArm64Emulator(Arm64Emulator):
    """自定义 ARM64 模拟器，继承自 Arm64Emulator"""
    
    def __init__(self, heap_base=0x1000000, heap_size=0x90000):
        """初始化模拟器"""
        super().__init__(heap_base, heap_size)
        self.BASE = 0
        self.END = 0
        self.run_range = (0, 0)
        self.auto_run_range = (0, 0)
        self.tpidr_value = None
        self.dump_config = {}
        self.last_regs = None  # 用于跟踪寄存器状态，类似 dyn_trace_ida.py

    def setup_from_files(self, load_path):
        """从文件设置模拟器参数"""
        # 读取基础地址
        with open(f"{load_path}/regs.json", "r") as f:
            tmp = json.load(f)
            self.dump_config = tmp
            self.BASE = int(tmp["base"], 16)
            self.END = int(tmp["end"], 16)
            run_start = int(tmp.get("run_start", tmp["base"]), 16)
            run_end = int(tmp.get("run_end", tmp["end"]), 16)
        
        # 自动范围来自base/end，实际运行范围优先使用run_start/run_end
        self.auto_run_range = (self.BASE, self.END)
        self.run_range = (run_start, run_end)
        
        return self.BASE

    def custom_main_trace(
        self,
        end_addr,
        so_name="",
        tenet_log_path=None,
        user_log_path="./uc.log",
        load_dumps_path="./dumps",
        user_hook_func=None
    ):
        """自定义主要模拟函数"""
        try:
            # 初始化日志文件
            self.init_log_files(tenet_log_path, user_log_path)
            
            # 加载内存映射
            self.load_memory_mappings(load_dumps_path)
            
            # 加载寄存器状态
            self.load_registers(os.path.join(load_dumps_path, "regs.json"))
            self.log("Registers loaded.")

            # 重置寄存器跟踪
            self.last_registers.clear()

            # 初始化trace日志
            if self.trace_log:
                self.init_trace_log(so_name or "", load_dumps_path)

            # 映射堆内存（检查是否已映射）
            try:
                # 尝试读取堆内存，如果成功则说明已映射
                self.mu.mem_read(self.HEAP_BASE, 1)
                self.log(f"[!] 堆内存已映射，跳过映射: {hex(self.HEAP_BASE)}-{hex(self.HEAP_BASE + self.HEAP_SIZE)}")
            except UcError:
                # 堆内存未映射，进行映射
                self.log(f"[+] 映射堆内存: {hex(self.HEAP_BASE)}-{hex(self.HEAP_BASE + self.HEAP_SIZE)} 大小: {hex(self.HEAP_SIZE)}")
                self.mu.mem_map(self.HEAP_BASE, self.HEAP_SIZE)

            # 设置调试钩子（先清理之前的钩子）
            self.hooks.clear()
            start_addr = self.mu.reg_read(self.REG_MAP["pc"])
            self.hooks.append(self.mu.hook_add(UC_HOOK_CODE, self.debug_hook_code, begin=start_addr))
            
            if user_hook_func != None:
                self.hooks.append(self.mu.hook_add(
                    UC_HOOK_CODE,
                    lambda uc, addr, size, user_data: user_hook_func(self, uc, addr, size),
                    begin=start_addr
                ))
            # 开始模拟
            self.mu.emu_start(start_addr, end_addr)

        except UcError as e:
            return self._handle_uc_error(e)
        except Exception as e:
            self.log(f"发生未知错误: {e}")
            self.my_reg_logger()
            return 0
        finally:
            self.log(f"Trace END!")
            # 清理资源
            self.cleanup()
        
        return 114514

    def _handle_uc_error(self, e):
        """处理Unicorn错误，与dyn_trace_ida.py保持一致"""
        self.log("ERROR: %s" % e)
        err_str = "%s" % e
        self.my_reg_logger()

        # 检查errno == 0的情况
        if e.errno == 0:
            self.log(e.args[0])
            if "Code Run out of range" in e.args[0]:
                return self._handle_out_of_range_error()
            if "Except AUTIASP" in e.args[0]:
                return self._handle_autiasp_error()

        # 检查异常错误
        if "UC_ERR_EXCEPTION" in err_str:
            return self._handle_exception_error()
            
        # 检查寄存器是否没有变化
        if self.last_regs == self.dump_registers():
            self.log(f"[!] Stop at the same location. Jump out. Maybe Check MRS opcode and TPIDR regs")
            return 0
        
        # 检查未映射内存错误
        if any(err in err_str for err in ["UC_ERR_READ_UNMAPPED", "UC_ERR_FETCH_UNMAPPED", "UC_ERR_WRITE_UNMAPPED"]):
            self.last_regs = self.dump_registers()
            return 2
        
        return 0

    def _handle_out_of_range_error(self):
        """处理超出范围错误"""
        self.log(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['lr']):x} for further run, PC: 0x{self.mu.reg_read(self.REG_MAP['pc']):x} ")
        self.log("[+] 超出范围，继续下一个dump文件夹")
        return 1

    def _handle_autiasp_error(self):
        """处理AUTIASP错误"""
        self.log(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['pc']) + 4:x} for further run, PC: 0x{self.mu.reg_read(self.REG_MAP['pc']):x} ")
        self.log("[+] AUTIASP指令，继续下一个dump文件夹")
        return 1

    def _handle_exception_error(self):
        """处理异常错误"""
        self.log(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['lr']):x} for further run")
        self.log("[+] 异常错误，继续下一个dump文件夹")
        return 1

# ==============================
# 辅助函数
# ==============================

def get_sorted_dump_folders(dump_path: str):
    """获取并按照时间戳排序的dump文件夹列表"""
    dump_folders = []
    for f in os.listdir(dump_path):
        pattern = r"dump_(\d+)$"
        match = re.match(pattern, f)
        if match:
            timestamp = int(match.group(1))
            dump_folders.append((timestamp, f))
    
    # 按时间戳升序排序（从早到晚）
    dump_folders.sort(key=lambda x: x[0])
    return [folder for _, folder in dump_folders]

def create_output_directory(base_path: str, prefix="continuous_output"):
    """创建输出目录"""
    output_dir = f"{base_path}/{prefix}_{int(time.time())}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

# ==============================
# 主函数
# ==============================

def _resolve_end_addr(base: int, end_addr_input: int, end_addr_absolute: bool) -> int:
    """根据输入模式解析结束地址"""
    if end_addr_absolute:
        return end_addr_input
    return base + end_addr_input


def _resolve_so_name_from_dump(dump_cfg: dict, so_name_input: str = None) -> str:
    """优先使用显式so_name，否则从dump参数读取，最终回退为空字符串"""
    if so_name_input:
        return so_name_input
    cfg_so_name = dump_cfg.get("so_name")
    if isinstance(cfg_so_name, str):
        return cfg_so_name
    return ""


def _parse_optional_int(value):
    """解析可选整数，支持int与十六进制字符串"""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return None
        if text.startswith("-0x") or text.startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    return None


def _resolve_end_addr_from_dump(base: int, dump_cfg: dict, end_addr_input, end_addr_absolute):
    """优先使用dump参数解析结束地址，显式传参可覆盖"""
    cfg_resolved_end = _parse_optional_int(dump_cfg.get("resolved_end_addr"))
    cfg_end_input = _parse_optional_int(dump_cfg.get("end_addr_input"))
    cfg_end_absolute = dump_cfg.get("end_addr_absolute")
    if isinstance(cfg_end_absolute, str):
        cfg_end_absolute = cfg_end_absolute.lower() == "true"
    elif cfg_end_absolute is None:
        cfg_end_absolute = False
    else:
        cfg_end_absolute = bool(cfg_end_absolute)

    if end_addr_input is None:
        if cfg_resolved_end is not None:
            return cfg_resolved_end, True
        if cfg_end_input is not None:
            return _resolve_end_addr(base, cfg_end_input, cfg_end_absolute), cfg_end_absolute
        raise ValueError("未提供 end_addr_input，且dump参数中也没有结束地址")

    if end_addr_absolute is None:
        effective_absolute = cfg_end_absolute
    else:
        effective_absolute = bool(end_addr_absolute)

    return _resolve_end_addr(base, end_addr_input, effective_absolute), effective_absolute


def _resolve_run_range(
    auto_range: tuple,
    base: int,
    bound_start: int = None,
    bound_end: int = None,
    bound_is_relative: bool = False
):
    """解析运行范围，若未提供自定义bound则返回自动范围"""
    if bound_start is None or bound_end is None:
        return auto_range

    if bound_is_relative:
        resolved_start = base + bound_start
        resolved_end = base + bound_end
    else:
        resolved_start = bound_start
        resolved_end = bound_end

    if resolved_start >= resolved_end:
        print("[!] 自定义bound无效（start >= end），回退到自动范围")
        return auto_range

    return (resolved_start, resolved_end)


def main(
    end_addr_input:int = None,
    so_name: str = None,
    tpidr_value_input: int = None,
    load_path:str = ".",
    save_path:str = ".",
    end_addr_absolute: bool = None,
    bound_start: int = None,
    bound_end: int = None,
    bound_is_relative: bool = False,
):
    """主函数"""
    print("Emulate ARM64 code")
    
    # 创建模拟器实例
    emulator = SelfRunArm64Emulator()

    # 从文件设置基础参数
    BASE = emulator.setup_from_files(load_path)
    dump_cfg = emulator.dump_config

    # 设置TPIDR：显式传参优先，否则读取dump参数
    if tpidr_value_input is not None:
        emulator.tpidr_value = tpidr_value_input
    else:
        emulator.tpidr_value = _parse_optional_int(dump_cfg.get("tpidr"))
    
    # 计算结束地址：优先读取dump参数
    end_addr, effective_end_addr_absolute = _resolve_end_addr_from_dump(
        BASE,
        dump_cfg,
        end_addr_input,
        end_addr_absolute,
    )
    resolved_so_name = _resolve_so_name_from_dump(dump_cfg, so_name)

    # 运行范围：默认用dump时记录的run_range，仅在显式传入bound时覆盖
    if bound_start is not None and bound_end is not None:
        emulator.run_range = _resolve_run_range(
            emulator.auto_run_range,
            BASE,
            bound_start=bound_start,
            bound_end=bound_end,
            bound_is_relative=bound_is_relative,
        )
    print(f"[+] 自动范围: {hex(emulator.auto_run_range[0])} - {hex(emulator.auto_run_range[1])}")
    print(f"[+] 运行范围: {hex(emulator.run_range[0])} - {hex(emulator.run_range[1])}")
    print(f"[+] SO Name: {resolved_so_name if resolved_so_name else '<empty>'}")
    print(f"[+] TPIDR: {hex(emulator.tpidr_value) if emulator.tpidr_value is not None else 'None'}")
    print(f"[+] 结束地址: {hex(end_addr)} ({'absolute' if effective_end_addr_absolute else 'relative'})")
    
    # 执行模拟
    result_code = emulator.custom_main_trace(
        end_addr,
        so_name=resolved_so_name,
        user_log_path=f"{save_path}/sim.log",
        tenet_log_path=f"{save_path}/tenet.log",
        load_dumps_path=load_path
    )
    print("[+] Finish!")
    return result_code

def combine_logs(path, pattern, output_filename):
    """Combine all log files matching pattern into output file, sorted by timestamp/numeric order, removing extra newlines."""
    import os, re, glob
    
    files = glob.glob(f'{path}/**/{pattern}', recursive=True)
    if not files:
        print(f"No {pattern} files found")
        return False
    
    def extract_sort_key(filepath):
        """Extract numeric key from filepath for sorting.
        Priority: segment_<number>, dump_<timestamp>, else modification time."""
        # Try to find segment_<number> in parent directories
        dirname = os.path.dirname(filepath)
        # Look for segment_<number> pattern
        seg_match = re.search(r'segment_(\d+)', dirname)
        if seg_match:
            return (0, int(seg_match.group(1)))  # type 0 for segment
        # Look for dump_<timestamp> pattern
        dump_match = re.search(r'dump_(\d+)', dirname)
        if dump_match:
            return (1, int(dump_match.group(1)))  # type 1 for dump
        # Fallback: use modification time
        return (2, os.path.getmtime(filepath))
    
    # Sort files by extracted key
    files.sort(key=extract_sort_key)
    
    with open(output_filename, 'w', encoding='utf-8') as outfile:
        for i, file in enumerate(files):
            with open(file, 'r', encoding='utf-8') as infile:
                content = infile.read()
                # Remove leading and trailing newlines to avoid extra blank lines
                content = content.lstrip('\n').rstrip('\n')
                outfile.write(content)
                # Add a newline between files, but not after the last file
                if i < len(files) - 1:
                    outfile.write('\n')
    print(f"Combined {len(files)} files into {output_filename} (sorted)")
    return True

def run_all(dump_path:str, so_path:str=None, end_addr_relative:int=None, tdpr:int=None, so_name: str = None):
    """旧的run_all函数：独立执行每个dump文件夹"""
    files = os.listdir(dump_path)
    for i in files:
        pattern = r"dump_\d+$"
        match = re.search(pattern, i)
        if match :
            main(end_addr_input=end_addr_relative,
                so_name=so_name,
                tpidr_value_input=tdpr,
                load_path=f"{dump_path}/{i}",
                save_path=f"{dump_path}/{i}")

    combine_logs(dump_path,'uc.log', 'combined_uc.log')
    combine_logs(dump_path,'sim.log', 'combined_sim.log')
    combine_logs(dump_path,'tenet.log', 'combined_tenet.log')

def run_all_continuous(
    dump_path:str,
    end_addr_input:int = None,
    so_name: str = None,
    tdpr:int=None,
    user_hook_func=None,
    debug_switch=False,
    end_addr_absolute: bool = None,
    bound_start: int = None,
    bound_end: int = None,
    bound_is_relative: bool = False,
):
    """
    新的连续执行函数：从前面往后面执行，跳过外部调用并合并
    
    参数:
        dump_path: dump文件夹路径
        end_addr_input: 目标地址输入
        tdpr: TPIDR寄存器值 (无需填写)
    
    返回:
        emulator: 模拟器
    """
    # 1. 获取并排序 dump 文件夹
    dump_folders = get_sorted_dump_folders(dump_path)
    if not dump_folders:
        print("[-] 没有找到dump文件夹")
        return False
    
    print(f"[+] 找到 {len(dump_folders)} 个dump文件夹，按时间排序:")
    for folder in dump_folders:
        print(f"  - {folder}")
    
    # 2. 创建输出目录
    output_dir = create_output_directory(dump_path, "continuous_output")
    
    # 3. 初始化日志文件
    combined_sim_log_path = f"{output_dir}/continuous_sim.log"
    combined_tenet_log_path = f"{output_dir}/continuous_tenet.log"
    
    combined_sim_log = open(combined_sim_log_path, "w")
    combined_tenet_log = open(combined_tenet_log_path, "w")
    
    # 4. 提取so文件名    
    # 5. 创建模拟器实例
    emulator = SelfRunArm64Emulator()
    emulator.tpidr_value = tdpr
    
    # 6. 处理第一个dump文件夹获取基础地址
    first_folder = dump_folders[0]
    first_path = f"{dump_path}/{first_folder}"
    BASE = emulator.setup_from_files(first_path)
    dump_cfg = emulator.dump_config
    emulator.debug = debug_switch
    if tdpr is not None:
        emulator.tpidr_value = tdpr
    else:
        emulator.tpidr_value = _parse_optional_int(dump_cfg.get("tpidr"))

    end_addr, effective_end_addr_absolute = _resolve_end_addr_from_dump(
        BASE,
        dump_cfg,
        end_addr_input,
        end_addr_absolute,
    )
    resolved_so_name = _resolve_so_name_from_dump(dump_cfg, so_name)
    if bound_start is not None and bound_end is not None:
        emulator.run_range = _resolve_run_range(
            emulator.auto_run_range,
            BASE,
            bound_start=bound_start,
            bound_end=bound_end,
            bound_is_relative=bound_is_relative,
        )
    
    print(f"[+] 基础地址: {hex(BASE)}")
    print(f"[+] 自动范围: {hex(emulator.auto_run_range[0])} - {hex(emulator.auto_run_range[1])}")
    print(f"[+] 运行范围: {hex(emulator.run_range[0])} - {hex(emulator.run_range[1])}")
    print(f"[+] SO Name: {resolved_so_name if resolved_so_name else '<empty>'}")
    print(f"[+] TPIDR: {hex(emulator.tpidr_value) if emulator.tpidr_value is not None else 'None'}")
    print(f"[+] 目标地址: {hex(end_addr)} ({'absolute' if effective_end_addr_absolute else 'relative'})")
    
    # 7. 循环处理所有dump文件夹
    success = False
    for i, folder in enumerate(dump_folders):
        dump_folder_path = f"{dump_path}/{folder}"
        print(f"\n[+] 处理第 {i+1}/{len(dump_folders)} 个dump文件夹: {folder}")
        # 创建当前片段的输出目录
        segment_dir = f"{output_dir}/segment_{i:03d}"
        os.makedirs(segment_dir, exist_ok=True)
        
        # 执行模拟
        result_code = emulator.custom_main_trace(
            end_addr,
            so_name=resolved_so_name,
            user_log_path=f"{segment_dir}/sim.log",
            tenet_log_path=f"{segment_dir}/tenet.log",
            load_dumps_path=dump_folder_path,
            user_hook_func=user_hook_func
        )
        
        # 合并日志
        try:
            with open(f"{segment_dir}/sim.log", "r") as f:
                combined_sim_log.write(f.read())
            with open(f"{segment_dir}/tenet.log", "r") as f:
                combined_tenet_log.write(f.read())
        except Exception as e:
            print(f"[-] 合并日志时出错: {e}")
        
        print(f"[+] 执行结果码: {result_code}")
        
        # 检查执行结果（与dyn_trace_ida.py保持一致）
        if result_code == 114514 :
            print("[+] 成功到达目标地址")
            success = True
            break
        elif result_code == 1:
            print("[+] 遇到外部调用或超出范围，继续下一个dump文件夹")
            # 注意：这里需要状态传递，但当前模拟器不支持
            # 暂时简单继续，实际需要保存和恢复状态
            continue
        elif result_code == 2:
            print("[+] 需要更新内存，出现错误")
            break
        elif result_code == 0:
            print(f"[!] 遇到错误，结果码: 0")
            print("[!] 停止执行")
            break
        elif result_code == 5:
            print("[!] 起始地址等于结束地址")
            break
        else:
            print(f"[!] 遇到未知结果码: {result_code}")
            break

    # 8. 关闭日志文件
    combined_sim_log.close()
    combined_tenet_log.close()
    
    # 9. 输出结果
    if success :
        print(f"\n[✓] 连续执行成功完成！")
    else:
        print(f"\n[!] 连续执行未完成")
    
    print(f"[+] 输出目录: {output_dir}")
    print(f"[+] 合并的日志文件:")
    print(f"    - {combined_sim_log_path}")
    print(f"    - {combined_tenet_log_path}")
    
    # 10. 也合并uc.log（如果有的话）
    combine_logs(output_dir, 'sim.log', f"{output_dir}/all_sim.log")
    combine_logs(output_dir, 'tenet.log', f"{output_dir}/all_tenet.log")
    combine_logs(dump_path, 'uc.log', f"{output_dir}/all_uc.log")
    
    return emulator

def run_once(
    dump_path:str,
    so_path:str=None,
    end_addr_input:int = None,
    so_name: str = None,
    tdpr:int=None,
    end_addr_absolute: bool = None,
    bound_start: int = None,
    bound_end: int = None,
    bound_is_relative: bool = False,
):
    result = main(
        end_addr_input=end_addr_input,
        so_name=so_name,
        tpidr_value_input=tdpr,
        load_path=dump_path,
        save_path=dump_path,
        end_addr_absolute=end_addr_absolute,
        bound_start=bound_start,
        bound_end=bound_end,
        bound_is_relative=bound_is_relative,
    )
    return result

if __name__ == "__main__":
    
    success = run_all_continuous(
        "tmp"
    )
    
