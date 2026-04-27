from local_emu import run_all_continuous

user_log = open("./user.log", "w+")

def user_hook(emulator, uc, address, size):
    """用户日志记录hook，跟踪strb、ldrb、xor指令"""
    offset = address - emulator.BASE
    code = emulator.mu.mem_read(address, 4)

    emulator.md.detail = True
    insn = next(emulator.md.disasm(code, address), None)

    if not insn:
        print(f"{hex(address):<12}: <Unknown Coding>")
        return

    content = emulator._format_instruction_operands(insn)
    # 基本指令打印
    print(f"{hex(address):<12}: {insn.mnemonic:<8} {insn.op_str:<24} {content:<50}")

    global user_log
    # 动态记录并打印 strb / ldrb
    if insn.mnemonic == "ldrb":
        contain = content.split(" ")
        if "wzr" in contain[1]:
            i1 = 0
        else:
            i1 = int(contain[1][2:], 16)
        if len(contain) == 3:
            i2 = int(contain[2][2:], 16)
            inum = ((i1 + i2) & 0xffffffffffffffff)
            index = i2
        else:
            inum = i1
            index = i1
        print(f"read self: {hex(inum):<15} {hex(index):<5} {emulator.mu.mem_read(inum, 0x1).hex():<5}", file=user_log)

    if insn.mnemonic == "strb":
        contain = content.split(" ")
        if "wzr" in contain[1]:
            i1 = 0
        else:
            i1 = int(contain[1][2:], 16)
        if len(contain) == 3:
            i2 = int(contain[2][2:], 16)
            inum = ((i1 + i2) & 0xffffffffffffffff)
        else:
            inum = i1
        
        index = 0xffffffff

        contain[0] = contain[0][-2:]
        print(f"save unkw: {hex(inum):<15} {hex(index):<5} {contain[0]:<5}", file=user_log)
        print(f"------------------------------------------------------------", file=user_log)

    # xor指令特殊处理
    if insn.mnemonic == "eor":
        contain = content.split(" ")
        i1 = int(contain[1][2:], 16) & 0xff
        i2 = int(contain[2][2:], 16) & 0xff
        inum = (i1 ^ i2)
        print(f"xor      : {hex(i1):<10} {hex(i2):<10} {hex(inum):<5}", file=user_log)

success = run_all_continuous(
    "./tmp",
    0x0000,
    user_hook_func=user_hook,
    debug_switch=True
)
