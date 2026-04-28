import time
import json
import re
import os
import capstone
from unicorn import *
from unicorn.arm64_const import *
import ida_segment
import idc
import ida_bytes
import idaapi
import ida_dbg
from unicorn_trace.unicorn_class import Arm64Emulator # type: ignore

# ==============================
# 常量定义
# ==============================

DUMP_SINGLE_SEG_SIZE = 0x4000
ROUND_MAX = 1000

# ==============================
# 插件表单类
# ==============================

class UnicornEmulatorForm(idaapi.Form):
    """Unicorn模拟器配置表单"""
    
    def __init__(self, auto_base: int, auto_end: int):
        auto_range_text = f"{hex(auto_base)} - {hex(auto_end)}"
        idaapi.Form.__init__(self, f"""STARTITEM 0
Unicorn ARM64 Emulator

Auto Range (from IDB): {auto_range_text}
<##END addr (hex)                  :{{end_addr}}>
<##So Name (Enter when enale tenet):{{so_name}}>
<##TPIDR (hex, optional)           :{{tpidr_value}}>
<##Bound start (hex)               :{{bound_start}}>
<##Bound end (hex)                 :{{bound_end}}>
<##output path (defalt .)          :{{output_path}}>
<##Check boxes##enable Tenet:{{enable_tenet}}><use custom bound:{{use_custom_bound}}><end addr absolute:{{end_addr_absolute}}>{{enable_group}}>
""", {
            'end_addr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,swidth=30),
            'so_name': idaapi.Form.StringInput(swidth=30,value=""),
            'tpidr_value': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,swidth=30,value=0),
            'bound_start': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,swidth=30,value=auto_base),
            'bound_end': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,swidth=30,value=auto_end),
            'output_path': idaapi.Form.StringInput(swidth=30,value="."),
            'enable_group': idaapi.Form.ChkGroupControl(("enable_tenet", "use_custom_bound", "end_addr_absolute")),
        })
        
        self.end_addr = 0x0000
        self.so_name = ""
        self.tpidr_value = None
        self.enable_tenet = False
        self.use_custom_bound = False
        self.end_addr_absolute = False
        self.bound_start = auto_base
        self.bound_end = auto_end
        self.output_path = "."

# ==============================
# 插件主类
# ==============================

class UnicornEmulatorPlugin(idaapi.plugin_t):
    """Unicorn ARM64模拟器插件"""
    
    flags = idaapi.PLUGIN_UNL
    comment = "ARM64 Unicorn Emulator"
    help = "使用Unicorn引擎模拟ARM64代码执行"
    wanted_name = "Unicorn ARM64 Emulator"
    wanted_hotkey = "Ctrl-Alt-U"

    def init(self):
        """初始化插件"""
        print("Unicorn ARM64 Emulator Plugin loaded")
        print("Use Ctrl-Alt-U to open the emulator")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        """运行插件"""
        try:
            auto_base = idaapi.get_imagebase()
            text_seg = ida_segment.get_segm_by_name(".text")
            if text_seg:
                auto_end = text_seg.end_ea
            else:
                print("[-] Cannot FOUND .text seg")
                return

            # 创建并显示配置表单
            form = UnicornEmulatorForm(auto_base, auto_end)
            form.Compile()
            
            ok = form.Execute()
            if ok == 1:
                # 获取表单数据
                end_addr_input = form.end_addr.value
                so_name = form.so_name.value
                tpidr_value = form.tpidr_value.value if form.tpidr_value.value != 0 else None
                flags = form.enable_group.value
                enable_tenet = bool(flags & 0x1)
                use_custom_bound = bool(flags & 0x2)
                end_addr_absolute = bool(flags & 0x4)
                bound_start = form.bound_start.value
                bound_end = form.bound_end.value
                output_path = form.output_path.value

                print(f"[+] 配置参数:")
                print(f"自动范围: {hex(auto_base)} - {hex(auto_end)}")
                print(f"结束地址输入: {hex(end_addr_input)} ({'absolute' if end_addr_absolute else 'relative'})")
                print(f"SO名称: {so_name}")
                if tpidr_value:
                    print(f"TPIDR值: {hex(tpidr_value)}")
                print(f"启用Tenet: {enable_tenet}")
                if use_custom_bound:
                    print(f"自定义Bound: {hex(bound_start)} - {hex(bound_end)}")
                else:
                    print("自定义Bound: 未启用（使用自动范围）")
                print(f"输出路径: {output_path}")
                # 创建模拟器实例并运行
                if end_addr_input != None:
                    uni_trace_main(
                        endaddr_input=end_addr_input,
                        so_name=so_name,
                        tpidr_value_input=tpidr_value,
                        enable_tenet=enable_tenet,
                        user_path=output_path,
                        end_addr_absolute=end_addr_absolute,
                        use_custom_bound=use_custom_bound,
                        bound_start=bound_start,
                        bound_end=bound_end,
                    )
                else:
                    print("[+] Wrong Input")
                
            form.Free()
            
        except Exception as e:
            print(f"插件运行错误: {e}")
            import traceback
            traceback.print_exc()

    def term(self):
        """终止插件"""
        pass

# ==============================
# 插件注册
# ==============================

def PLUGIN_ENTRY():
    """插件入口点"""
    return UnicornEmulatorPlugin()

# ==============================
# 原有的IDA集成ARM64模拟器类（保持不变）
# ==============================

class IDAArm64Emulator(Arm64Emulator):
    """IDA集成的ARM64模拟器，继承自Arm64Emulator基类"""
    def remove_last_line_efficient(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            if lines:
                lines.pop()  # 删除最后一行
                with open(filename, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
        except Exception as e:
            return
    
    def init_log_files(self, tenet_log_path, user_log_path):
        """初始化日志文件"""
        if tenet_log_path:
            # self.remove_last_line_efficient(tenet_log_path)
            self.trace_log = open(tenet_log_path, "a")
            # self.trace_log.write("\n")
        
        if user_log_path:
            # self.remove_last_line_efficient(user_log_path)
            self.log_file = open(user_log_path, "a")
            # self.log_file.write("\n")

    def __init__(self, heap_base=0x1000000, heap_size=0x90000):
        """初始化IDA集成模拟器"""
        # 调用父类初始化
        super().__init__(heap_base, heap_size)
        
        # IDA特定的变量

        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.dumped_range = []
        self.dump_path = "./dumps"
        self.last_regs = None
        self.BASE = 0
        self.run_range = (0, 0)

    # ==============================
    # 重写父类方法 - 主要模拟
    # ==============================
    def load_memory_mappings(self, load_dumps_path):
        """重写：加载内存映射，集成IDA段信息"""
        mem_list = os.listdir(load_dumps_path)
        map_list = []
        
        # 解析内存映射文件
        for filename in mem_list:
            pattern = r'0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)\.bin$'
            match = re.search(pattern, filename)
            if match:
                mem_base = int(match.group(1), 16)
                mem_end = int(match.group(2), 16)
                mem_size = int(match.group(3), 16)
                map_list.append((mem_base, mem_end, mem_size, filename))

        # 按照内存基址排序后加载
        map_list.sort(key=lambda x: x[0])
        self.map_range.sort(key=lambda x: x[0])

        new_map_range = []
        current_start, current_end = None, None

        for start, end in self.map_range:
            if current_end is None:
                current_start, current_end = start, end
            elif current_end == start:
                current_end = end
            else:
                new_map_range.append((current_start, current_end))
                current_start, current_end = start, end

        # 添加最后一个区间
        if current_start is not None:
            new_map_range.append((current_start, current_end))

        self.map_range = new_map_range

        for mem_base, mem_end, mem_size, filename in map_list:
            if filename in self.loaded_files:
                continue

            upper_bound = mem_base
            lower_bound = mem_end

            for mem_range in self.map_range:
                if upper_bound <= mem_range[1] and upper_bound >= mem_range[0]:
                    if upper_bound < mem_range[1]:
                        upper_bound = mem_range[1]

                if lower_bound <= mem_range[1] and lower_bound >= mem_range[0]:
                    if lower_bound > mem_range[0]:
                        lower_bound = mem_range[0]

            if mem_base < upper_bound:
                mem_base = upper_bound
            if mem_base & 0xfff != 0:
                mem_base = mem_base & 0xfffffffffffff000

            if mem_end > lower_bound:
                mem_end = lower_bound
            
            mem_size = mem_end - mem_base

            # if mem_size <= 0:
            #     mem_size = 0x1000            
            if mem_size <= 0:
                self.log(f"continue: map file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}, bound ({hex(upper_bound)} - {hex(lower_bound)})")
                continue

            elif mem_size & 0xfff != 0:
                mem_size = (mem_size & 0xfffffffffffff000) + 0x1000

            mem_end = mem_base + mem_size

            self.log(f"map file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}, bound ({hex(upper_bound)} - {hex(lower_bound)})")
            self.mu.mem_map(mem_base, mem_size)
            self.map_range.append((mem_base, mem_end))

        # 加载内存数据
        for mem_base, mem_end, mem_size, filename in map_list:
            if filename not in self.loaded_files:
                self.log(f"write file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}")
                self.load_file(os.path.join(load_dumps_path, filename), mem_base, mem_size)
                self.loaded_files.append(filename)

    def main_trace(self, so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps"):
        """重写：主要模拟函数，集成IDA错误处理"""
        try:        
            # 初始化日志文件
            self.init_log_files(tenet_log_path, user_log_path)
            
            if self.loaded_files == []:

                # 加载寄存器状态
                self.load_registers(os.path.join(load_dumps_path, "regs.json"))
                print("Registers loaded.")  

                # 重置寄存器跟踪
                self.last_registers.clear()

                # 初始化trace日志
                if self.trace_log:
                    self.init_trace_log(so_name, load_dumps_path)

                self.hooks.append(self.mu.hook_add(UC_HOOK_CODE, self.debug_hook_code))

            # 加载内存映射
            self.load_memory_mappings(load_dumps_path)

            # 设置调试钩子
            start_addr = self.mu.reg_read(self.REG_MAP["pc"])

            if end_addr == start_addr:
                return 5
            # 开始模拟
            self.mu.emu_start(start_addr, end_addr)

        except UcError as e:
            return self._handle_uc_error(e)
        except Exception as e:
            print(f"发生未知错误: {e}")    
            self.my_reg_logger()
            return 0
        finally:
            print(f"Trace END!")
            # 清理资源
            if self.log_file:
                self.log_file.close()
            if self.trace_log:
                self.trace_log.close()
        
        return 114514

    def _handle_uc_error(self, e):
        """重写：处理Unicorn错误，集成IDA错误处理"""
        print("ERROR: %s" % e)
        err_str = "%s" % e
        self.my_reg_logger()

        if e.errno == 0:
            if "Code Run out of range" in e.args[0]:
                return self._handle_out_of_range_error()
            if "Except AUTIASP" in e.args[0]:
                return self._handle_autiasp_error()

        if "UC_ERR_EXCEPTION" in err_str:
            return self._handle_exception_error()
            
        if self.last_regs == self.dump_registers():
            print(f"[!] Stop at the same location. Jump out. Maybe Check MRS opcode and TPIDR regs")
            return 0
        
        if any(err in err_str for err in ["UC_ERR_READ_UNMAPPED", "UC_ERR_FETCH_UNMAPPED", "UC_ERR_WRITE_UNMAPPED"]):
            self.last_regs = self.dump_registers()
            return 2
        
        return 0

    def _handle_out_of_range_error(self):
        """处理超出范围错误"""
        if self.check_registers():
            print('[!] Check REGs Wrong')
            exit(0)

        print(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['lr']):x} for further run, PC: 0x{self.mu.reg_read(self.REG_MAP['pc']):x} ")
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP['lr']))
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        print(f"[+] Restart this Script until finish")
        return 1

    def _handle_autiasp_error(self):
        """处理AUTIASP错误"""
        if self.check_registers():
            print('[!] Check REGs Wrong')
            exit(0)

        print(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['pc']) + 4:x} for further run, PC: 0x{self.mu.reg_read(self.REG_MAP['pc']):x} ")
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP['pc']) + 4)
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        print(f"[+] Restart this Script until finish")
        return 1

    def _handle_exception_error(self):
        """处理异常错误"""
        if self.check_registers():
            print('[!] Check REGs Wrong')
            exit(0)
        
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP['lr']))
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        print(f"[+] Restart this Script until finish")
        return 1

    # ==============================
    # IDA特定的方法
    # ==============================

    def dump_segment_to_file(self, seg_start, seg_end, filename):
        """转储段数据到文件"""
        try:
            seg_size = seg_end - seg_start
            if seg_size <= 0:
                print(f"[-] Invalid segment size: {seg_size}")
                return False
            
            if seg_size > 0x4000000:
                print(f"[!] Too big segment size: {seg_size}")
                seg_size = 0x4000000
            
            segment_data = ida_bytes.get_bytes(seg_start, seg_size)
            if not segment_data:
                print(f"[-] Failed to read segment data from {hex(seg_start)} to {hex(seg_end)}")
                return False
            
            with open(filename, 'wb') as f:
                f.write(segment_data)
            
            print(f"[+] Successfully dumped segment to: {filename}")
            print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
            print(f"[+] Dumped size: {len(segment_data)} bytes ({hex(len(segment_data))})")
            return True
            
        except Exception as e:
            print(f"[-] Error during dump: {str(e)}")
            return False

    def find_segment_by_address(self, target_addr):
        """通过地址查找段"""
        try:
            if isinstance(target_addr, str):
                addr_val = int(target_addr, 16) if target_addr.startswith('0x') else int(target_addr)
            else:
                addr_val = target_addr
        except ValueError:
            print(f"[-] Invalid address format: {target_addr}")
            return None
        
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg and seg.start_ea <= addr_val < seg.end_ea:
                return seg
        
        print(f"[-] No segment found containing address: {hex(addr_val)}")
        return None

    def dump_single_segment_address(self, input_addr, range_size=0x10000, file_dump_path="./dumps", next_dump_flag=False):
        """转储单个段地址"""
        if not input_addr:
            print("[-] No address provided")
            return
        
        if isinstance(input_addr, str):
            target_addr = int(input_addr[2:], 16) if input_addr.startswith('0x') else int(input_addr)
        else:
            target_addr = input_addr

        # 处理特殊地址格式
        if target_addr & 0xb4ff000000000000 == 0xb400000000000000:
            target_addr = target_addr & 0xffffffffffffff
        
        seg = self.find_segment_by_address(target_addr)
        if not seg:
            print(f"[+] {target_addr} do not contain the addr")
            return
        
        # 计算转储范围
        if range_size < 0x10000:
            dump_base = target_addr & (~(0x1000 - 1))
        else:
            dump_base = target_addr & (~(range_size - 1))

        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        
        print(f"[+] Found segment: {seg_name}")
        print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
        print(f"[+] Segment size: {hex(seg_end - seg_start)} bytes")
        
        dump_end = dump_base + range_size
        if dump_end > seg_end:
            dump_end = seg_end
        if dump_base < seg_start:
            dump_base = seg_start
        
        # 检查是否已转储
        for exist_start, exist_end in self.dumped_range:
            if dump_base > exist_start and dump_base < exist_end:
                dump_base = exist_end
            if dump_end > exist_start and dump_end < exist_end:
                dump_end = exist_start
        
        if dump_base >= dump_end:
            print(f"[+] Range {hex(dump_base)} - {hex(dump_end)} already dumped")
            return
        
        self.dumped_range.append((dump_base, dump_end))
        
        # 生成输出文件名
        filename = f"{file_dump_path}/segment_{seg_name}_{hex(dump_base)}_{hex(dump_end)}_{hex(dump_end - dump_base)}.bin"
        
        # 转储段到文件
        self.dump_segment_to_file(dump_base, dump_end, filename)

        # 处理跨段读写
        if next_dump_flag:
            tmp_addr = seg_end
            while tmp_addr < dump_base + range_size:
                self.dump_single_segment_address(tmp_addr + 1, range_size, file_dump_path, False)
                tmp_seg = self.find_segment_by_address(tmp_addr + 1)
                if not tmp_seg:
                    print(f"[+] {target_addr} do not contain the addr")
                    return

                tmp_addr += tmp_seg.end_ea - tmp_seg.start_ea


    def dump_registers_memory(self):    
        """转储寄存器指向的内存，包括当前指令可能访问的内存地址"""
        try:
            # 获取当前PC
            current_pc = self.mu.reg_read(self.REG_MAP["pc"])
            
            # 获取前一条指令的地址（因为当前PC可能已经指向下一条指令）
            prev_inst_addr = current_pc
            
            try:
                # 读取指令
                code = self.mu.mem_read(prev_inst_addr, 4)
                # 反汇编指令
                insn = next(self.md.disasm(code, prev_inst_addr), None)
                
                if insn:
                    # 检查是否是内存加载指令
                    if any(insn.mnemonic.startswith(prefix) for prefix in self.READ_INSTRUCTIONS):
                        self.log(f"[+] 分析内存加载指令: {insn.mnemonic} {insn.op_str}")
                        
                        # 分析内存操作数
                        memory_addresses = self._analyze_memory_operands_for_dump(insn)
                        
                        if memory_addresses:
                            for addr in memory_addresses:
                                self.log(f"[+] 需要dump的内存地址: {hex(addr)}")
                                self.dump_single_segment_address(addr, DUMP_SINGLE_SEG_SIZE, self.dump_path, True)
                                return
                        else:
                            self.log("[!] 无法解析内存地址")
            except Exception as e:
                self.log(f"[!] 分析指令时出错: {e}")
            
        except Exception as e:
            self.log(f"[!] 获取当前PC时出错: {e}")
        
        # 同时转储所有寄存器指向的内存（原有逻辑）
        for reg_name in self.REG_MAP.keys():
            if "w" in reg_name or "tpidr" in reg_name:
                continue
            try:
                reg_value = self.mu.reg_read(self.REG_MAP[reg_name])
                self.dump_single_segment_address(reg_value, DUMP_SINGLE_SEG_SIZE, self.dump_path, True)
            except Exception as e:
                self.log(f"[!] 读取寄存器 {reg_name} 时出错: {e}")

    def _analyze_memory_operands_for_dump(self, insn):
        """专门用于dump的内存操作数分析"""
        memory_addresses = []
        
        for op in insn.operands:
            if op.type == capstone.CS_OP_MEM:
                mem = op.value.mem
                base_reg = insn.reg_name(mem.base) if mem.base != 0 else None
                index_reg = insn.reg_name(mem.index) if mem.index != 0 else None
                disp = mem.disp
                
                try:
                    # 获取基址寄存器的值
                    base_val = 0
                    if base_reg:
                        if base_reg in self.REG_MAP:
                            base_val = self.mu.reg_read(self.REG_MAP[base_reg])
                        else:
                            # 处理特殊寄存器如xzr/wzr（零寄存器）
                            if base_reg in ['xzr', 'wzr']:
                                base_val = 0
                            else:
                                self.log(f"[!] 未知基址寄存器: {base_reg}")
                                continue
                    
                    # 获取索引寄存器的值
                    index_val = 0
                    if index_reg:
                        if index_reg in self.REG_MAP:
                            index_val = self.mu.reg_read(self.REG_MAP[index_reg])
                        else:
                            if index_reg in ['xzr', 'wzr']:
                                index_val = 0
                            else:
                                self.log(f"[!] 未知索引寄存器: {index_reg}")
                                continue
                    
                    # 计算内存地址
                    mem_addr = base_val
                    if index_reg:
                        # 检查是否有比例因子（scale）
                        if hasattr(mem, 'scale') and mem.scale != 1:
                            mem_addr += index_val * mem.scale
                        else:
                            mem_addr += index_val
                    mem_addr += disp
                    mem_addr = mem_addr & 0xFFFFFFFFFFFFFFFF
                    
                    memory_addresses.append(mem_addr)
                    
                    # 记录详细日志
                    self.log(f"  - 内存访问: {insn.mnemonic}")
                    # self.log(f"    基址寄存器: {base_reg} = {hex(base_val)}")
                    # if index_reg:
                    #     self.log(f"    索引寄存器: {index_reg} = {hex(index_val)}")
                    # if disp != 0:
                    #     self.log(f"    偏移量: {hex(disp)}")
                    self.log(f"    计算地址: {hex(mem_addr)}")
                    
                except Exception as e:
                    self.log(f"[!] 计算内存地址时出错: {e}")
                    self.log(f"    指令: {insn.mnemonic} {insn.op_str}")
        
        return memory_addresses

    def check_registers(self):
        """检查寄存器一致性"""
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP["pc"]))
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

        for reg_name in self.REG_MAP.keys():
            if "w" in reg_name or "tpidr" in reg_name:
                continue
            uc_value = self.mu.reg_read(self.REG_MAP[reg_name])
            ida_value = idc.get_reg_value(reg_name)
            if ida_value & 0xb4ff000000000000 == 0xb400000000000000:
                ida_value = ida_value & 0xffffffffffffff
            print(f"{reg_name} uc: 0x{uc_value:x} ida: 0x{ida_value:x}")
            if uc_value != ida_value:
                return True 
        return False

    def _collect_register_state(self):
        """收集寄存器状态"""
        registers = {}
        registers["sp"] = hex(idc.get_reg_value("sp"))
        registers["pc"] = hex(idc.get_reg_value("pc"))
        
        for i in range(31):
            reg_value = idc.get_reg_value(f"x{i}")
            # 处理特殊地址格式
            if reg_value & 0xb4ff000000000000 == 0xb400000000000000:
                reg_value = reg_value & 0xffffffffffffff
            print(f"x{i} = " + hex(reg_value))
            registers[f"x{i}"] = hex(reg_value)
                
        return registers

# ==============================
# 主函数 - 集成原有脚本的main函数
# ==============================

def uni_trace_main(
    endaddr_input:int,
    so_name: str = "",
    tpidr_value_input: int = None,
    enable_tenet=False,
    user_path:str = ".",
    end_addr_absolute: bool = False,
    use_custom_bound: bool = False,
    bound_start: int = None,
    bound_end: int = None,
):
    """主函数 - 集成原有脚本的main函数功能"""
    total_log = open(user_path + f"/uc_combine_{str(int(time.time()))}.log", "w+")

    dump_round = 0
    while dump_round < ROUND_MAX:
        print("Emulate ARM64 code")
        emulator = IDAArm64Emulator()

        # 创建转储目录
        now_time_stamp = str(int(time.time()))
        emulator.dump_path = f"{user_path}/dump_{now_time_stamp}"
        os.mkdir(emulator.dump_path)

        # 收集寄存器状态
        registers = emulator._collect_register_state()
        
        emulator.BASE = idaapi.get_imagebase()

        text_seg = ida_segment.get_segm_by_name(".text")
        if text_seg:
            auto_end = text_seg.end_ea
            emulator.END = auto_end
        else:
            print("[-] Cannot FOUND .text seg")
            break

        auto_range = (emulator.BASE, auto_end)
        if use_custom_bound:
            if bound_start is None or bound_end is None or bound_start >= bound_end:
                print("[!] 自定义Bound无效，回退到自动范围")
                emulator.run_range = auto_range
            else:
                emulator.run_range = (bound_start, bound_end)
        else:
            emulator.run_range = auto_range

        print(f"[+] BASE = {hex(emulator.BASE)} END = {hex(auto_end)}")
        print(f"[+] Auto Range = {hex(auto_range[0])} - {hex(auto_range[1])}")
        print(f"[+] Run Range  = {hex(emulator.run_range[0])} - {hex(emulator.run_range[1])}")
        print("[+] DUMPING memory")
        
        # 转储寄存器指向的内存
        for reg_value in registers.values():
            if isinstance(reg_value, str):
                reg_value = int(reg_value, 16)
            emulator.dump_single_segment_address(reg_value, DUMP_SINGLE_SEG_SIZE, emulator.dump_path, True)
        
        # 保存寄存器状态
        if tpidr_value_input != None:
            registers["tpidr"] = hex(tpidr_value_input)

        if end_addr_absolute:
            end_addr = endaddr_input
        else:
            end_addr = emulator.BASE + endaddr_input

        registers["base"] = hex(emulator.BASE)
        registers["end"] = hex(auto_end)
        registers["run_start"] = hex(emulator.run_range[0])
        registers["run_end"] = hex(emulator.run_range[1])
        registers["end_addr_input"] = hex(endaddr_input)
        registers["end_addr_absolute"] = bool(end_addr_absolute)
        registers["resolved_end_addr"] = hex(end_addr)
        registers["use_custom_bound"] = bool(use_custom_bound)
        if bound_start is not None:
            registers["bound_start"] = hex(bound_start)
        if bound_end is not None:
            registers["bound_end"] = hex(bound_end)
        registers["enable_tenet"] = bool(enable_tenet)
        if so_name:
            registers["so_name"] = so_name

        print("[+] DUMPING registers")
        with open(f"{emulator.dump_path}/regs.json", "w+") as f:
            json.dump(registers, f)

        emulator.tpidr_value = tpidr_value_input
        result_code = 11400
        
        if enable_tenet:
            _tenet_log_path = f"{emulator.dump_path}/tenet.log"
        else:
            _tenet_log_path = None

        # 执行模拟
        while result_code != 114514:
            result_code = emulator.main_trace(so_name, end_addr, 
                                        user_log_path=f"{emulator.dump_path}/uc.log", 
                                        tenet_log_path=_tenet_log_path,
                                        load_dumps_path=emulator.dump_path)
            if result_code == 2:
                print("Update Memory")
                emulator.dump_registers_memory()
            else:
                break

        dump_round += 1
        
        with open(f"{emulator.dump_path}/uc.log", "r") as tmp:
            total_log.write(tmp.read())

        # 检查退出条件
        if result_code == 1:
            print("[+] restart ")
            continue
        
        if result_code == 0:
            print("[!] Something Wrong")
            break

        if result_code == 5:
            print("[!] Start address = End Address")
            break
        # 检查最终状态
        if emulator.mu.reg_read(emulator.REG_MAP["pc"]) == end_addr:
            if emulator.check_registers():
                print("[!] REGs check Wrong, Breakpoint could lead to this error")
            else:
                print("[+] Finish!")
        else:
            print("[!] Something Wrong")
        break
    total_log.close()


if __name__ == "__main__":
    # 创建IDA集成模拟器实例
    
    # 运行模拟
    uni_trace_main(0x0000, tpidr_value_input=None)
    
    # 清理资源
