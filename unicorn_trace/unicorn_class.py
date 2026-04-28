import json
import re
import os
import capstone
from unicorn import *
from unicorn.arm64_const import *

class Arm64Emulator:
    """ARM64 模拟器类"""
    
    # 寄存器映射常量
    REG_MAP = {
        # General purpose registers (64-bit)
        "x0": UC_ARM64_REG_X0, "x1": UC_ARM64_REG_X1, "x2": UC_ARM64_REG_X2, "x3": UC_ARM64_REG_X3,
        "x4": UC_ARM64_REG_X4, "x5": UC_ARM64_REG_X5, "x6": UC_ARM64_REG_X6, "x7": UC_ARM64_REG_X7,
        "x8": UC_ARM64_REG_X8, "x9": UC_ARM64_REG_X9, "x10": UC_ARM64_REG_X10, "x11": UC_ARM64_REG_X11,
        "x12": UC_ARM64_REG_X12, "x13": UC_ARM64_REG_X13, "x14": UC_ARM64_REG_X14, "x15": UC_ARM64_REG_X15,
        "x16": UC_ARM64_REG_X16, "x17": UC_ARM64_REG_X17, "x18": UC_ARM64_REG_X18, "x19": UC_ARM64_REG_X19,
        "x20": UC_ARM64_REG_X20, "x21": UC_ARM64_REG_X21, "x22": UC_ARM64_REG_X22, "x23": UC_ARM64_REG_X23,
        "x24": UC_ARM64_REG_X24, "x25": UC_ARM64_REG_X25, "x26": UC_ARM64_REG_X26, "x27": UC_ARM64_REG_X27,
        "x28": UC_ARM64_REG_X28, "x29": UC_ARM64_REG_X29, "x30": UC_ARM64_REG_X30,
        
        # General purpose registers (32-bit)
        "w0": UC_ARM64_REG_W0, "w1": UC_ARM64_REG_W1, "w2": UC_ARM64_REG_W2, "w3": UC_ARM64_REG_W3,
        "w4": UC_ARM64_REG_W4, "w5": UC_ARM64_REG_W5, "w6": UC_ARM64_REG_W6, "w7": UC_ARM64_REG_W7,
        "w8": UC_ARM64_REG_W8, "w9": UC_ARM64_REG_W9, "w10": UC_ARM64_REG_W10, "w11": UC_ARM64_REG_W11,
        "w12": UC_ARM64_REG_W12, "w13": UC_ARM64_REG_W13, "w14": UC_ARM64_REG_W14, "w15": UC_ARM64_REG_W15,
        "w16": UC_ARM64_REG_W16, "w17": UC_ARM64_REG_W17, "w18": UC_ARM64_REG_W18, "w19": UC_ARM64_REG_W19,
        "w20": UC_ARM64_REG_W20, "w21": UC_ARM64_REG_W21, "w22": UC_ARM64_REG_W22, "w23": UC_ARM64_REG_W23,
        "w24": UC_ARM64_REG_W24, "w25": UC_ARM64_REG_W25, "w26": UC_ARM64_REG_W26, "w27": UC_ARM64_REG_W27,
        "w28": UC_ARM64_REG_W28, "w29": UC_ARM64_REG_W29, "w30": UC_ARM64_REG_W30,
        
        # Special registers
        "pc": UC_ARM64_REG_PC, "sp": UC_ARM64_REG_SP, "fp": UC_ARM64_REG_X29, "lr": UC_ARM64_REG_X30,

        "tpidr": UC_ARM64_REG_TPIDR_EL0
    }
    
    # 内存访问指令常量
    READ_INSTRUCTIONS = ['ldr', 'ldrb', 'ldrh', 'ldp', 'ldur', 'ldurb', 'ldurh', 'ldxr', 'ldar']
    WRITE_INSTRUCTIONS = ['str', 'strb', 'strh', 'stp', 'stur', 'sturb', 'sturh', 'stxr', 'star']
    READ_WRITE_INSTRUCTIONS = ['ldaxr', 'stlxr']
    
    # 跟踪的寄存器列表
    TRACKED_REGS = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
        "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
        "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
        "x30", "sp", "pc"
    ]

    def __init__(self, heap_base=0x1000000, heap_size=0x90000):
        """初始化模拟器"""
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            # 初始化模拟器
        self.md.detail = True
        
        self.trace_log = None
        self.log_file = None
        self.last_registers = {}
        self.hooks = []
        
        self.BASE = 0
        self.END = 0
        self.HEAP_BASE = heap_base
        self.HEAP_SIZE = heap_size
        self.PHEAP = heap_base
        self.tpidr_value = None
        self.run_range = (0, 0)
        
        self.check_contain = []
        self.now_contain = ""
        
        self.loaded_files = []
        self.map_range = []
        self.debug = True

    def log(self, *args, **kwargs):
        """根据 debug 开关打印信息"""
        if self.debug:
            print(*args, **kwargs)
    # ==============================
    # 内存管理方法
    # ==============================

    def load_file(self, path, start, size):
        """从文件加载数据到模拟器内存"""
        with open(path, "rb") as fp:
            self.mu.mem_write(start, fp.read())

    def load_registers(self, path):
        """从JSON文件加载寄存器状态"""
        with open(path) as f:
            registers = json.load(f)
            for reg_name, value in registers.items():
                if reg_name in self.REG_MAP:
                    if isinstance(value, str):
                        value = int(value, 16)
                    self.log(f"Setting {reg_name} to {hex(value)}")
                    self.mu.reg_write(self.REG_MAP[reg_name], value)

    def dump_registers(self):
        """保存或返回所有寄存器状态"""
        registers = {}
        for reg_name, reg_const in self.REG_MAP.items():
            try:
                value = self.mu.reg_read(reg_const)
                registers[reg_name] = value
            except Exception as e:
                registers[reg_name] = f"Error: {str(e)}"
        
        result = ["Register Dump:"]
        for reg_name in sorted(registers.keys()):
            value = registers[reg_name]
            if isinstance(value, int):
                result.append(f"  {reg_name:8} = {hex(value)}")
            else:
                result.append(f"  {reg_name:8} = {value}")
        return "\n".join(result)

    # ==============================
    # 工具方法
    # ==============================

    def bytearray_to_int(self, byte_array):
        """字节数组转整数（小端序）"""
        return int.from_bytes(byte_array, byteorder='little')

    def read_pointer(self, address):
        """从指定地址读取指针"""
        return self.bytearray_to_int(self.mu.mem_read(address, 4))

    def extract_bit_field(self, input_value, start_bit, end_bit):
        """提取位字段"""
        mask = (~(-1 << (end_bit - start_bit)) << start_bit)
        return (mask & input_value) >> start_bit

    def read_reg_from_instruction(self, inst_input, index):
        """从指令中读取寄存器值"""
        return self.mu.reg_read(self.REG_MAP[inst_input.reg_name(inst_input.operands[index].value.reg)])

    # ==============================
    # Hook处理方法
    # ==============================

    def my_malloc_impl(self, size):
        """malloc实现"""
        self.log(f"[+] malloc size {hex(size)}")
        self.PHEAP += size
        return self.PHEAP

    def my_malloc_handler(self, uc, address, size, user_data):
        """malloc hook处理"""
        self.log(f"[+] INTO Malloc {self.mu.reg_read(UC_ARM64_REG_X0)} LR = {hex(self.mu.reg_read(UC_ARM64_REG_LR))}")
        uc.reg_write(UC_ARM64_REG_X0, self.my_malloc_impl(self.mu.reg_read(UC_ARM64_REG_X0)))
        uc.reg_write(UC_ARM64_REG_PC, self.mu.reg_read(UC_ARM64_REG_LR))

    def my_free_handler(self, uc, address, size, user_data):
        """free hook处理"""
        self.log(f"[+] free NOP")
        uc.reg_write(UC_ARM64_REG_PC, self.mu.reg_read(UC_ARM64_REG_LR))

    def my_memset_impl(self, ptr, value, num):
        """memset实现"""
        self.log(f"[+] memset ptr {hex(ptr)}, value {hex(value)}, size {hex(num)}")
        return ptr

    def my_memset_handler(self, uc, address, size, user_data):
        """memset hook处理"""
        self.log(f"[+] INTO Memset")
        ptr = self.mu.reg_read(UC_ARM64_REG_X0)
        value = self.mu.reg_read(UC_ARM64_REG_X1)
        num = self.mu.reg_read(UC_ARM64_REG_X2)
        
        result = self.my_memset_impl(ptr, value, num)
        
        uc.reg_write(UC_ARM64_REG_X0, result)
        uc.reg_write(UC_ARM64_REG_PC, self.mu.reg_read(UC_ARM64_REG_LR))

    # ==============================
    # 内存访问分析
    # ==============================

    def analyze_memory_access(self, insn, address):
        """分析指令的内存访问模式"""
        memory_accesses = []
        
        for op in insn.operands:
            if op.type == capstone.CS_OP_MEM:
                mem = op.value.mem
                base_reg = insn.reg_name(mem.base) if mem.base != 0 else None
                index_reg = insn.reg_name(mem.index) if mem.index != 0 else None
                disp = mem.disp
                
                try:
                    base_val = self.mu.reg_read(self.REG_MAP[base_reg]) if base_reg else 0
                    index_val = self.mu.reg_read(self.REG_MAP[index_reg]) if index_reg else 0
                    
                    mem_addr = base_val
                    if index_reg:
                        if hasattr(mem, 'scale') and mem.scale != 1:
                            mem_addr += index_val * mem.scale
                        else:
                            mem_addr += index_val
                    mem_addr += disp
                    mem_addr = mem_addr & 0xFFFFFFFFFFFFFFFF
                    
                    # 处理读取指令
                    if any(insn.mnemonic.startswith(prefix) for prefix in self.READ_INSTRUCTIONS):
                        access_size = self._get_memory_access_size(insn)
                        try:
                            data = self.mu.mem_read(mem_addr, access_size)
                            hex_bytes = data.hex()
                            if 'p' in insn.mnemonic and access_size == 16 and len(hex_bytes) != 32:
                                hex_bytes = hex_bytes.ljust(32, '0')[:32]
                            memory_accesses.append(f"mr=0x{mem_addr:x}:{hex_bytes}")
                        except Exception as e:
                            self.log(f"内存读取错误: {e} - 指令: {insn.mnemonic} {insn.op_str}")
                    
                    # 处理写入指令
                    elif any(insn.mnemonic.startswith(prefix) for prefix in self.WRITE_INSTRUCTIONS):
                        if len(insn.operands) >= 2 and insn.operands[0].type == capstone.CS_OP_REG:
                            src_reg = insn.reg_name(insn.operands[0].value.reg)
                            try:
                                reg_val = 0 if src_reg in ['wzr', 'xzr'] else self.mu.reg_read(self.REG_MAP[src_reg])
                                access_size, data = self._get_write_data(insn, src_reg, reg_val)
                                hex_bytes = data.hex()
                                if 'p' in insn.mnemonic and access_size == 16 and len(hex_bytes) != 32:
                                    hex_bytes = hex_bytes.ljust(32, '0')[:32]
                                memory_accesses.append(f"mw=0x{mem_addr:x}:{hex_bytes}")
                            except Exception as e:
                                self.log(f"内存写入错误: {e} - 指令: {insn.mnemonic} {insn.op_str}")
                                
                except Exception as e:
                    self.log(f"计算内存地址错误: {e} - 指令: {insn.mnemonic} {insn.op_str}")
                    
        return memory_accesses

    def _get_memory_access_size(self, insn):
        """获取内存访问大小"""
        if 'b' in insn.mnemonic:  # 字节
            return 1
        elif 'h' in insn.mnemonic:  # 半字
            return 2
        elif 'p' in insn.mnemonic:  # 对加载/存储
            return 16
        elif insn.operands[0].type == capstone.CS_OP_REG:
            reg_name = insn.reg_name(insn.operands[0].value.reg)
            return 4 if reg_name.startswith('w') else 8
        else:
            return 8

    def _get_write_data(self, insn, src_reg, reg_val):
        """获取写入数据"""
        if 'b' in insn.mnemonic:  # 字节
            return 1, (reg_val & 0xFF).to_bytes(1, 'little')
        elif 'h' in insn.mnemonic:  # 半字
            return 2, (reg_val & 0xFFFF).to_bytes(2, 'little')
        elif 'p' in insn.mnemonic:  # 对存储
            if len(insn.operands) >= 3 and insn.operands[1].type == capstone.CS_OP_REG:
                src_reg2 = insn.reg_name(insn.operands[1].value.reg)
                reg_val2 = 0 if src_reg2 in ['wzr', 'xzr'] else self.mu.reg_read(self.REG_MAP[src_reg2])
                return 16, reg_val.to_bytes(8, 'little') + reg_val2.to_bytes(8, 'little')
            else:
                return 8, reg_val.to_bytes(8, 'little')
        elif src_reg.startswith('w') or src_reg == 'wzr':  # 32位寄存器
            return 4, (reg_val & 0xFFFFFFFF).to_bytes(4, 'little')
        else:  # 64位寄存器
            return 8, reg_val.to_bytes(8, 'little')

    # ==============================
    # 寄存器跟踪
    # ==============================

    def log_changed_registers(self):
        """只记录发生变化的寄存器"""
        current_registers = {}
        changed_regs = []
        
        for reg_name in self.TRACKED_REGS:
            if reg_name in self.REG_MAP:
                value = self.mu.reg_read(self.REG_MAP[reg_name])
                current_registers[reg_name] = value
                
                if reg_name not in self.last_registers or self.last_registers[reg_name] != value:
                    changed_regs.append((reg_name, value))
        
        self.last_registers.update(current_registers)
        
        if changed_regs:
            reg_output = [f"{reg_name.upper()}={hex(value)}" for reg_name, value in changed_regs]
            return ",".join(reg_output)
        return None

    # ==============================
    # 日志记录
    # ==============================

    def tenet_trace_log(self, address):
        """Trace钩子 - 通过分析汇编指令记录内存访问"""
        code = self.mu.mem_read(address, 4)
        insn = next(self.md.disasm(code, address), None)
        
        if not insn:
            return
        
        memory_accesses = self.analyze_memory_access(insn, address)
        changed_regs_line = self.log_changed_registers()
        
        tmp_buffer = ""
        if changed_regs_line and self.trace_log:
            tmp_buffer += changed_regs_line
        
        output_line = ""
        if memory_accesses:
            output_line += "," + ",".join(memory_accesses)
        if not "PC" in tmp_buffer:
            tmp_buffer += "," + f"PC=0x{address:x}"
        if self.trace_log:
            self.trace_log.write(tmp_buffer + output_line + "\n")

    def print_user_log(self, address):
        """用户日志记录"""
        offset = address - self.BASE
        code = self.mu.mem_read(address, 4)
        
        self.md.detail = True
        insn = next(self.md.disasm(code, address), None)
        
        if not insn:
            print(f"{hex(address):<12}: <Unknown Coding>", file=self.log_file)
            return

        content = self._format_instruction_operands(insn)
        print(f"{hex(address):<12}: {insn.mnemonic:<8} {insn.op_str:<24} {content:<50}", file=self.log_file)

    def _format_instruction_operands(self, insn):
        """格式化指令操作数"""
        content_parts = []
        
        for i, op in enumerate(insn.operands):
            if i > 0:
                content_parts.append(" ")
                
            if op.type == capstone.CS_OP_REG:
                reg_name = insn.reg_name(op.value.reg)
                try:
                    reg_val = self.mu.reg_read(self.REG_MAP[reg_name])
                    content_parts.append(f"{hex(reg_val)}")
                except KeyError:
                    content_parts.append(f"<Unknown REG:{reg_name}>")
                    
            elif op.type == capstone.CS_OP_IMM:
                content_parts.append(f"{hex(op.value.imm)}")
                
            elif op.type == capstone.CS_OP_MEM:
                mem = op.value.mem
                if mem.base != 0:
                    base_reg = insn.reg_name(mem.base)
                    try:
                        base_val = self.mu.reg_read(self.REG_MAP[base_reg])
                        content_parts.append(f"{hex(base_val)}")
                    except KeyError:
                        content_parts.append(f"<Unknown REG:{base_reg}>")
                        
                if mem.index != 0:
                    index_reg = insn.reg_name(mem.index)
                    try:
                        index_val = self.mu.reg_read(self.REG_MAP[index_reg])
                        content_parts.append(f" {hex(index_val)}")
                    except KeyError:
                        content_parts.append(f" <Unknown REG:{index_reg}>")
                        
                if mem.disp != 0:
                    content_parts.append(f" {hex(mem.disp)}")
                    
            elif op.type == capstone.CS_OP_FP:
                content_parts.append(f"{op.value.fp}")
                
            else:
                content_parts.append(f"<OPCODE TYPE:{op.type}>")
        
        return "".join(content_parts)

    # ==============================
    # 调试钩子
    # ==============================

    def debug_hook_code(self, uc, address, size, user_data):
        """调试钩子，用于其他调试目的"""
        # 检查执行范围
        if address <= self.run_range[0] or address >= self.run_range[1]:
            self.log("OUT OF RANGE")
            raise UcError(0, f"Code Run out of range (0x{self.run_range[0]:x}, 0x{self.run_range[1]:x})")
        
        # 处理特殊指令
        code = self.mu.mem_read(address, 4)
        if code == b"\xBF\x23\x03\xD5":  # handle autiasp
            raise UcError(0, "Except AUTIASP")

        code = self.mu.mem_read(address, 4)
        if code == b"\x01\x00\x00\xD4":  # handle autiasp
            raise UcError(0, "Except AUTIASP")
        
        # 处理寄存器值修正
        self._fix_register_values()
        
        # 调用 trace 日志记录函数
        if self.trace_log:
            self.tenet_trace_log(address)
        if self.log_file:
            self.print_user_log(address)

    def _fix_register_values(self):
        """修正寄存器值"""
        for i in range(31):
            reg_tmp_num = self.mu.reg_read(self.REG_MAP[f"x{i}"])
            if reg_tmp_num & 0xb4ff000000000000 == 0xb400000000000000:
                reg_tmp_num = reg_tmp_num & 0xffffffffffffff
                self.mu.reg_write(self.REG_MAP[f"x{i}"], reg_tmp_num)

    def my_reg_logger(self):
        """打印寄存器状态"""
        self.log("PC :", hex(self.mu.reg_read(UC_ARM64_REG_PC)))
        self.log("SP :", hex(self.mu.reg_read(UC_ARM64_REG_SP)))
        self.log("NZCV:", hex(self.mu.reg_read(UC_ARM64_REG_NZCV)))
        
        reg_names = [
            ("x0", UC_ARM64_REG_X0), ("x1", UC_ARM64_REG_X1),
            ("x2", UC_ARM64_REG_X2), ("x3", UC_ARM64_REG_X3),
            ("x4", UC_ARM64_REG_X4), ("x5", UC_ARM64_REG_X5),
            ("x6", UC_ARM64_REG_X6), ("x7", UC_ARM64_REG_X7),
            ("x8", UC_ARM64_REG_X8), ("x9", UC_ARM64_REG_X9),
            ("x10", UC_ARM64_REG_X10), ("x11", UC_ARM64_REG_X11),
            ("x12", UC_ARM64_REG_X12), ("x13", UC_ARM64_REG_X13),
            ("x14", UC_ARM64_REG_X14), ("x15", UC_ARM64_REG_X15),
            ("x16", UC_ARM64_REG_X16), ("x17", UC_ARM64_REG_X17),
            ("x18", UC_ARM64_REG_X18), ("x19", UC_ARM64_REG_X19),
            ("x20", UC_ARM64_REG_X20), ("x21", UC_ARM64_REG_X21),
            ("x22", UC_ARM64_REG_X22), ("x23", UC_ARM64_REG_X23),
            ("x24", UC_ARM64_REG_X24), ("x25", UC_ARM64_REG_X25),
            ("x26", UC_ARM64_REG_X26), ("x27", UC_ARM64_REG_X27),
            ("x28", UC_ARM64_REG_X28), ("x29", UC_ARM64_REG_X29),
            ("x30", UC_ARM64_REG_X30)
        ]
        
        for i in range(0, len(reg_names), 4):
            for name, reg in reg_names[i:i+4]:
                value = self.mu.reg_read(reg)
                self.log(f"{name:<3}: {hex(value):<18}", end=" ")
            self.log()

    def dump_memory(self, filename, address, size):
        """转储内存到文件"""
        with open(filename, "wb") as f:
            f.write(self.mu.mem_read(address, size))
        self.log(f"Memory dumped to {filename}")

    # ==============================
    # 初始化方法
    # ==============================

    def init_log_files(self, tenet_log_path, user_log_path):
        """初始化日志文件"""
        if tenet_log_path:
            self.trace_log = open(tenet_log_path, "w")
        
        if user_log_path:
            self.log_file = open(user_log_path, "w")


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
            # if filename not in self.loaded_files:
            self.log(f"write file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}")
            self.load_file(os.path.join(load_dumps_path, filename), mem_base, mem_size)
            self.loaded_files.append(filename)

    def init_trace_log(self, so_name, dump_dir=None):
        """初始化trace日志"""
        if self.trace_log and dump_dir:
            self.trace_log.write(f"# DUMP_DIR: {os.path.abspath(dump_dir)}\n")
        # self.trace_log.write(f"# SO: {so_name} @ {hex(self.BASE)}\n")
        
        # 记录初始寄存器状态
        initial_regs = []
        for reg_name in self.TRACKED_REGS:
            if reg_name in self.REG_MAP:
                value = self.mu.reg_read(self.REG_MAP[reg_name])
                initial_regs.append(f"{reg_name.upper()}={hex(value)}")
                self.last_registers[reg_name] = value
        
        self.trace_log.write(",".join(initial_regs) + "\n")

    # ==============================
    # 主要模拟方法
    # ==============================

    def main_trace(self, so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps"):
        """主要模拟函数"""
        try:        
            
            # 初始化日志文件
            self.init_log_files(tenet_log_path, user_log_path)
            
            # 加载内存映射
            self.load_memory_mappings(load_dumps_path)
            
            # 设置线程指针
            if self.tpidr_value is not None:
                self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, self.tpidr_value)

            # 加载寄存器状态
            self.load_registers(os.path.join(load_dumps_path, "regs.json"))
            self.log("Registers loaded.")  

            # 重置寄存器跟踪
            self.last_registers.clear()

            # 初始化trace日志
            if self.trace_log:
                self.init_trace_log(so_name, load_dumps_path)

            # 映射堆内存
            self.mu.mem_map(self.HEAP_BASE, self.HEAP_SIZE)

            # 设置调试钩子
            start_addr = self.mu.reg_read(self.REG_MAP["pc"])
            self.hooks.append(self.mu.hook_add(UC_HOOK_CODE, self.debug_hook_code, begin=start_addr))

            # 开始模拟
            self.mu.emu_start(start_addr, self.BASE + end_addr)

        except UcError as e:
            self.log("ERROR: %s" % e)
            self.my_reg_logger()
        except Exception as e:
            self.log(f"发生未知错误: {e}")    
            self.my_reg_logger()
        finally:
            self.my_reg_logger()
            # 记录最终寄存器状态
            if self.trace_log:
                self._write_final_registers()
        
        self.log(f"END!")    

        # 清理资源
        if self.log_file:
            self.log_file.close()
        if self.trace_log:
            self.trace_log.close()

    def _write_final_registers(self):
        """写入最终寄存器状态"""
        final_regs = []
        for reg_name in self.TRACKED_REGS:
            if reg_name in self.REG_MAP:
                value = self.mu.reg_read(self.REG_MAP[reg_name])
                final_regs.append(f"{reg_name.upper()}={hex(value)}")
        
        self.trace_log.write(",".join(final_regs) + "\n")

    # ==============================
    # 清理方法
    # ==============================

    def cleanup(self):
        """清理资源"""
        if self.log_file:
            self.log_file.close()
            self.log_file = None
        if self.trace_log:
            self.trace_log.close()
            self.trace_log = None
        
        # 移除所有钩子
        for hook in self.hooks:
            try:
                self.mu.hook_del(hook)
            except Exception as e:
                # 忽略钩子删除错误
                pass
        
        # 清空钩子列表
        self.hooks.clear()
