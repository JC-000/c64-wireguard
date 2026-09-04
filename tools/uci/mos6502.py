"""tools/uci/mos6502.py — a documented-opcode NMOS 6502 interpreter.

Why this exists
---------------
The multi-block SOCKET_READ path in src/net/uci/net.s is UCI-only, and VICE
does not emulate the Ultimate Command Interface at all ($DF1D reads $FF), so
`net_poll`'s block-drain loop cannot be reached in an emulator. This core
lets the REAL assembled bytes of that loop run on the host against a scripted
$DF1C-$DF1F device model, off hardware.

Scope and deliberate limits
---------------------------
* Documented opcodes only. An undocumented one raises `UnknownOpcode` rather
  than being guessed at — ca65 does not emit them, so a hit means the CPU
  went somewhere it should not have, which is information worth an exception.
* Decimal mode is refused (`SED` raises). Nothing in this codebase sets it,
  and a silently-wrong BCD ADC is exactly the kind of quiet infidelity that
  would make a test result meaningless.
* Cycle counts are the standard base counts plus the page-cross and
  branch-taken penalties. They exist to drive a CIA TOD model, not to
  measure code, so they are not claimed to be exact for every edge (e.g. the
  RMW abs,X always-5-reads case is charged its documented 7).
* No interrupts, no ROM, no VIC/SID/CIA beyond what the caller hooks.

The core is validated in-suite rather than on trust: the suite that uses it
first executes BLAKE2s out of the very same wireguard.prg over randomised
inputs and requires byte-exact agreement with hashlib. That is ~10^6
instructions across the full addressing-mode set per run; an ADC, an
indexed store or a page-crossing branch that were wrong would not survive it.
"""
from __future__ import annotations


class UnknownOpcode(Exception):
    def __init__(self, opcode: int, pc: int) -> None:
        super().__init__(f"undocumented/unknown opcode ${opcode:02X} at ${pc:04X}")
        self.opcode = opcode
        self.pc = pc


class CpuBudgetExceeded(Exception):
    pass


# mode names
IMP, ACC, IMM, ZP, ZPX, ZPY, ABS, ABX, ABY, IND, IZX, IZY, REL = range(13)

# opcode -> (mnemonic, mode, base_cycles)
_TABLE: dict[int, tuple[str, int, int]] = {
    0x69: ("ADC", IMM, 2), 0x65: ("ADC", ZP, 3), 0x75: ("ADC", ZPX, 4),
    0x6D: ("ADC", ABS, 4), 0x7D: ("ADC", ABX, 4), 0x79: ("ADC", ABY, 4),
    0x61: ("ADC", IZX, 6), 0x71: ("ADC", IZY, 5),
    0x29: ("AND", IMM, 2), 0x25: ("AND", ZP, 3), 0x35: ("AND", ZPX, 4),
    0x2D: ("AND", ABS, 4), 0x3D: ("AND", ABX, 4), 0x39: ("AND", ABY, 4),
    0x21: ("AND", IZX, 6), 0x31: ("AND", IZY, 5),
    0x0A: ("ASL", ACC, 2), 0x06: ("ASL", ZP, 5), 0x16: ("ASL", ZPX, 6),
    0x0E: ("ASL", ABS, 6), 0x1E: ("ASL", ABX, 7),
    0x90: ("BCC", REL, 2), 0xB0: ("BCS", REL, 2), 0xF0: ("BEQ", REL, 2),
    0x30: ("BMI", REL, 2), 0xD0: ("BNE", REL, 2), 0x10: ("BPL", REL, 2),
    0x50: ("BVC", REL, 2), 0x70: ("BVS", REL, 2),
    0x24: ("BIT", ZP, 3), 0x2C: ("BIT", ABS, 4),
    0x00: ("BRK", IMP, 7),
    0x18: ("CLC", IMP, 2), 0xD8: ("CLD", IMP, 2), 0x58: ("CLI", IMP, 2),
    0xB8: ("CLV", IMP, 2),
    0xC9: ("CMP", IMM, 2), 0xC5: ("CMP", ZP, 3), 0xD5: ("CMP", ZPX, 4),
    0xCD: ("CMP", ABS, 4), 0xDD: ("CMP", ABX, 4), 0xD9: ("CMP", ABY, 4),
    0xC1: ("CMP", IZX, 6), 0xD1: ("CMP", IZY, 5),
    0xE0: ("CPX", IMM, 2), 0xE4: ("CPX", ZP, 3), 0xEC: ("CPX", ABS, 4),
    0xC0: ("CPY", IMM, 2), 0xC4: ("CPY", ZP, 3), 0xCC: ("CPY", ABS, 4),
    0xC6: ("DEC", ZP, 5), 0xD6: ("DEC", ZPX, 6), 0xCE: ("DEC", ABS, 6),
    0xDE: ("DEC", ABX, 7),
    0xCA: ("DEX", IMP, 2), 0x88: ("DEY", IMP, 2),
    0x49: ("EOR", IMM, 2), 0x45: ("EOR", ZP, 3), 0x55: ("EOR", ZPX, 4),
    0x4D: ("EOR", ABS, 4), 0x5D: ("EOR", ABX, 4), 0x59: ("EOR", ABY, 4),
    0x41: ("EOR", IZX, 6), 0x51: ("EOR", IZY, 5),
    0xE6: ("INC", ZP, 5), 0xF6: ("INC", ZPX, 6), 0xEE: ("INC", ABS, 6),
    0xFE: ("INC", ABX, 7),
    0xE8: ("INX", IMP, 2), 0xC8: ("INY", IMP, 2),
    0x4C: ("JMP", ABS, 3), 0x6C: ("JMP", IND, 5),
    0x20: ("JSR", ABS, 6),
    0xA9: ("LDA", IMM, 2), 0xA5: ("LDA", ZP, 3), 0xB5: ("LDA", ZPX, 4),
    0xAD: ("LDA", ABS, 4), 0xBD: ("LDA", ABX, 4), 0xB9: ("LDA", ABY, 4),
    0xA1: ("LDA", IZX, 6), 0xB1: ("LDA", IZY, 5),
    0xA2: ("LDX", IMM, 2), 0xA6: ("LDX", ZP, 3), 0xB6: ("LDX", ZPY, 4),
    0xAE: ("LDX", ABS, 4), 0xBE: ("LDX", ABY, 4),
    0xA0: ("LDY", IMM, 2), 0xA4: ("LDY", ZP, 3), 0xB4: ("LDY", ZPX, 4),
    0xAC: ("LDY", ABS, 4), 0xBC: ("LDY", ABX, 4),
    0x4A: ("LSR", ACC, 2), 0x46: ("LSR", ZP, 5), 0x56: ("LSR", ZPX, 6),
    0x4E: ("LSR", ABS, 6), 0x5E: ("LSR", ABX, 7),
    0xEA: ("NOP", IMP, 2),
    0x09: ("ORA", IMM, 2), 0x05: ("ORA", ZP, 3), 0x15: ("ORA", ZPX, 4),
    0x0D: ("ORA", ABS, 4), 0x1D: ("ORA", ABX, 4), 0x19: ("ORA", ABY, 4),
    0x01: ("ORA", IZX, 6), 0x11: ("ORA", IZY, 5),
    0x48: ("PHA", IMP, 3), 0x08: ("PHP", IMP, 3),
    0x68: ("PLA", IMP, 4), 0x28: ("PLP", IMP, 4),
    0x2A: ("ROL", ACC, 2), 0x26: ("ROL", ZP, 5), 0x36: ("ROL", ZPX, 6),
    0x2E: ("ROL", ABS, 6), 0x3E: ("ROL", ABX, 7),
    0x6A: ("ROR", ACC, 2), 0x66: ("ROR", ZP, 5), 0x76: ("ROR", ZPX, 6),
    0x6E: ("ROR", ABS, 6), 0x7E: ("ROR", ABX, 7),
    0x40: ("RTI", IMP, 6), 0x60: ("RTS", IMP, 6),
    0xE9: ("SBC", IMM, 2), 0xE5: ("SBC", ZP, 3), 0xF5: ("SBC", ZPX, 4),
    0xED: ("SBC", ABS, 4), 0xFD: ("SBC", ABX, 4), 0xF9: ("SBC", ABY, 4),
    0xE1: ("SBC", IZX, 6), 0xF1: ("SBC", IZY, 5),
    0x38: ("SEC", IMP, 2), 0xF8: ("SED", IMP, 2), 0x78: ("SEI", IMP, 2),
    0x85: ("STA", ZP, 3), 0x95: ("STA", ZPX, 4), 0x8D: ("STA", ABS, 4),
    0x9D: ("STA", ABX, 5), 0x99: ("STA", ABY, 5), 0x81: ("STA", IZX, 6),
    0x91: ("STA", IZY, 6),
    0x86: ("STX", ZP, 3), 0x96: ("STX", ZPY, 4), 0x8E: ("STX", ABS, 4),
    0x84: ("STY", ZP, 3), 0x94: ("STY", ZPX, 4), 0x8C: ("STY", ABS, 4),
    0xAA: ("TAX", IMP, 2), 0xA8: ("TAY", IMP, 2), 0xBA: ("TSX", IMP, 2),
    0x8A: ("TXA", IMP, 2), 0x9A: ("TXS", IMP, 2), 0x98: ("TYA", IMP, 2),
}

# Ops that write their result back to memory: the address is resolved
# without a page-cross penalty (the 6502 always takes the fixed cycle count).
_RMW = {"ASL", "LSR", "ROL", "ROR", "INC", "DEC"}
_STORE = {"STA", "STX", "STY"}


class Mos6502:
    """A 6502 with a flat 64 KiB bytearray and one contiguous I/O window.

    `io_read(addr)` / `io_write(addr, value)` are consulted for every access
    in [io_lo, io_hi). Everything else is plain RAM. That is enough for this
    project: the PRG occupies $0801-$9FFF and the only devices net_poll
    touches are CIA1 ($DC00) and the UCI ($DF1B-$DF1F).
    """

    RETURN_SENTINEL = 0xFFF0

    def __init__(self, mem=None, io_read=None, io_write=None,
                 io_lo=0xDC00, io_hi=0xE000):
        self.mem = bytearray(0x10000) if mem is None else mem
        self._io_read = io_read
        self._io_write = io_write
        self.io_lo = io_lo
        self.io_hi = io_hi
        self.a = self.x = self.y = 0
        self.sp = 0xFD
        self.pc = 0
        self.c = self.z = self.v = self.n = 0
        self.i = 1
        self.d = 0
        self.cycles = 0
        self.instructions = 0
        self._ops = {name: getattr(self, "_op_" + name)
                     for name in {m for m, _, _ in _TABLE.values()}}

    # ---- bus -------------------------------------------------------------
    def rd(self, addr):
        if self.io_lo <= addr < self.io_hi:
            return self._io_read(addr) & 0xFF
        return self.mem[addr]

    def wr(self, addr, value):
        if self.io_lo <= addr < self.io_hi:
            self._io_write(addr, value & 0xFF)
            return
        self.mem[addr] = value & 0xFF

    def rd16(self, addr):
        return self.rd(addr) | (self.rd((addr + 1) & 0xFFFF) << 8)

    # ---- stack -----------------------------------------------------------
    def push(self, v):
        self.mem[0x100 + self.sp] = v & 0xFF
        self.sp = (self.sp - 1) & 0xFF

    def pop(self):
        self.sp = (self.sp + 1) & 0xFF
        return self.mem[0x100 + self.sp]

    @property
    def p(self):
        return ((self.n and 0x80) | (self.v and 0x40) | 0x20 |
                (self.d and 0x08) | (self.i and 0x04) |
                (self.z and 0x02) | (self.c and 0x01))

    @p.setter
    def p(self, v):
        self.n = 1 if v & 0x80 else 0
        self.v = 1 if v & 0x40 else 0
        self.d = 1 if v & 0x08 else 0
        self.i = 1 if v & 0x04 else 0
        self.z = 1 if v & 0x02 else 0
        self.c = v & 1

    # ---- driving ---------------------------------------------------------
    def call(self, addr, max_cycles=200_000_000):
        """JSR to `addr` from a sentinel return address; run until it RTSes.

        Returns the number of cycles the call took. Raises
        `CpuBudgetExceeded` if it does not return within `max_cycles` —
        a hang is a result, not a reason to wait forever.
        """
        ret = self.RETURN_SENTINEL - 1
        self.push((ret >> 8) & 0xFF)
        self.push(ret & 0xFF)
        self.pc = addr
        start = self.cycles
        while self.pc != self.RETURN_SENTINEL:
            self.step()
            if self.cycles - start > max_cycles:
                raise CpuBudgetExceeded(
                    f"call to ${addr:04X} did not return within "
                    f"{max_cycles} cycles (pc=${self.pc:04X})")
        return self.cycles - start

    def step(self):
        pc = self.pc
        op = self.mem[pc] if pc < self.io_lo or pc >= self.io_hi else self.rd(pc)
        try:
            name, mode, cyc = _TABLE[op]
        except KeyError:
            raise UnknownOpcode(op, pc) from None
        self.pc = (pc + 1) & 0xFFFF
        self.cycles += cyc
        self.instructions += 1
        self._ops[name](mode)

    # ---- addressing ------------------------------------------------------
    def _addr(self, mode, penalise=True):
        pc = self.pc
        if mode == IMM:
            self.pc = (pc + 1) & 0xFFFF
            return pc
        if mode == ZP:
            self.pc = (pc + 1) & 0xFFFF
            return self.mem[pc]
        if mode == ZPX:
            self.pc = (pc + 1) & 0xFFFF
            return (self.mem[pc] + self.x) & 0xFF
        if mode == ZPY:
            self.pc = (pc + 1) & 0xFFFF
            return (self.mem[pc] + self.y) & 0xFF
        if mode == ABS:
            self.pc = (pc + 2) & 0xFFFF
            return self.mem[pc] | (self.mem[pc + 1] << 8)
        if mode == ABX:
            self.pc = (pc + 2) & 0xFFFF
            base = self.mem[pc] | (self.mem[pc + 1] << 8)
            eff = (base + self.x) & 0xFFFF
            if penalise and (base & 0xFF00) != (eff & 0xFF00):
                self.cycles += 1
            return eff
        if mode == ABY:
            self.pc = (pc + 2) & 0xFFFF
            base = self.mem[pc] | (self.mem[pc + 1] << 8)
            eff = (base + self.y) & 0xFFFF
            if penalise and (base & 0xFF00) != (eff & 0xFF00):
                self.cycles += 1
            return eff
        if mode == IZX:
            self.pc = (pc + 1) & 0xFFFF
            zp = (self.mem[pc] + self.x) & 0xFF
            return self.mem[zp] | (self.mem[(zp + 1) & 0xFF] << 8)
        if mode == IZY:
            self.pc = (pc + 1) & 0xFFFF
            zp = self.mem[pc]
            base = self.mem[zp] | (self.mem[(zp + 1) & 0xFF] << 8)
            eff = (base + self.y) & 0xFFFF
            if penalise and (base & 0xFF00) != (eff & 0xFF00):
                self.cycles += 1
            return eff
        if mode == IND:
            self.pc = (pc + 2) & 0xFFFF
            ptr = self.mem[pc] | (self.mem[pc + 1] << 8)
            # NMOS page-wrap bug, deliberately reproduced.
            lo = self.rd(ptr)
            hi = self.rd((ptr & 0xFF00) | ((ptr + 1) & 0xFF))
            return lo | (hi << 8)
        raise AssertionError(f"bad mode {mode}")

    def _operand(self, mode):
        return self.rd(self._addr(mode))

    def _setzn(self, v):
        self.z = 1 if v == 0 else 0
        self.n = 1 if v & 0x80 else 0
        return v

    # ---- operations ------------------------------------------------------
    def _op_ADC(self, mode):
        if self.d:
            raise NotImplementedError("decimal-mode ADC is deliberately unsupported")
        m = self._operand(mode)
        t = self.a + m + self.c
        self.c = 1 if t > 0xFF else 0
        r = t & 0xFF
        self.v = 1 if (~(self.a ^ m) & (self.a ^ r) & 0x80) else 0
        self.a = self._setzn(r)

    def _op_SBC(self, mode):
        if self.d:
            raise NotImplementedError("decimal-mode SBC is deliberately unsupported")
        m = self._operand(mode) ^ 0xFF
        t = self.a + m + self.c
        self.c = 1 if t > 0xFF else 0
        r = t & 0xFF
        self.v = 1 if (~(self.a ^ m) & (self.a ^ r) & 0x80) else 0
        self.a = self._setzn(r)

    def _op_AND(self, mode):
        self.a = self._setzn(self.a & self._operand(mode))

    def _op_ORA(self, mode):
        self.a = self._setzn(self.a | self._operand(mode))

    def _op_EOR(self, mode):
        self.a = self._setzn(self.a ^ self._operand(mode))

    def _op_BIT(self, mode):
        m = self._operand(mode)
        self.z = 1 if (self.a & m) == 0 else 0
        self.n = 1 if m & 0x80 else 0
        self.v = 1 if m & 0x40 else 0

    def _cmp(self, reg, mode):
        m = self._operand(mode)
        t = (reg - m) & 0xFF
        self.c = 1 if reg >= m else 0
        self._setzn(t)

    def _op_CMP(self, mode):
        self._cmp(self.a, mode)

    def _op_CPX(self, mode):
        self._cmp(self.x, mode)

    def _op_CPY(self, mode):
        self._cmp(self.y, mode)

    def _op_ASL(self, mode):
        if mode == ACC:
            self.c = 1 if self.a & 0x80 else 0
            self.a = self._setzn((self.a << 1) & 0xFF)
            return
        a = self._addr(mode, penalise=False)
        m = self.rd(a)
        self.c = 1 if m & 0x80 else 0
        self.wr(a, self._setzn((m << 1) & 0xFF))

    def _op_LSR(self, mode):
        if mode == ACC:
            self.c = self.a & 1
            self.a = self._setzn(self.a >> 1)
            return
        a = self._addr(mode, penalise=False)
        m = self.rd(a)
        self.c = m & 1
        self.wr(a, self._setzn(m >> 1))

    def _op_ROL(self, mode):
        if mode == ACC:
            t = (self.a << 1) | self.c
            self.c = 1 if t > 0xFF else 0
            self.a = self._setzn(t & 0xFF)
            return
        a = self._addr(mode, penalise=False)
        t = (self.rd(a) << 1) | self.c
        self.c = 1 if t > 0xFF else 0
        self.wr(a, self._setzn(t & 0xFF))

    def _op_ROR(self, mode):
        if mode == ACC:
            t = self.a | (self.c << 8)
            self.c = t & 1
            self.a = self._setzn(t >> 1)
            return
        a = self._addr(mode, penalise=False)
        t = self.rd(a) | (self.c << 8)
        self.c = t & 1
        self.wr(a, self._setzn(t >> 1))

    def _op_INC(self, mode):
        a = self._addr(mode, penalise=False)
        self.wr(a, self._setzn((self.rd(a) + 1) & 0xFF))

    def _op_DEC(self, mode):
        a = self._addr(mode, penalise=False)
        self.wr(a, self._setzn((self.rd(a) - 1) & 0xFF))

    def _op_INX(self, mode):
        self.x = self._setzn((self.x + 1) & 0xFF)

    def _op_INY(self, mode):
        self.y = self._setzn((self.y + 1) & 0xFF)

    def _op_DEX(self, mode):
        self.x = self._setzn((self.x - 1) & 0xFF)

    def _op_DEY(self, mode):
        self.y = self._setzn((self.y - 1) & 0xFF)

    def _op_LDA(self, mode):
        self.a = self._setzn(self._operand(mode))

    def _op_LDX(self, mode):
        self.x = self._setzn(self._operand(mode))

    def _op_LDY(self, mode):
        self.y = self._setzn(self._operand(mode))

    def _op_STA(self, mode):
        self.wr(self._addr(mode, penalise=False), self.a)

    def _op_STX(self, mode):
        self.wr(self._addr(mode, penalise=False), self.x)

    def _op_STY(self, mode):
        self.wr(self._addr(mode, penalise=False), self.y)

    def _op_TAX(self, mode):
        self.x = self._setzn(self.a)

    def _op_TAY(self, mode):
        self.y = self._setzn(self.a)

    def _op_TXA(self, mode):
        self.a = self._setzn(self.x)

    def _op_TYA(self, mode):
        self.a = self._setzn(self.y)

    def _op_TSX(self, mode):
        self.x = self._setzn(self.sp)

    def _op_TXS(self, mode):
        self.sp = self.x

    def _op_PHA(self, mode):
        self.push(self.a)

    def _op_PLA(self, mode):
        self.a = self._setzn(self.pop())

    def _op_PHP(self, mode):
        self.push(self.p | 0x10)

    def _op_PLP(self, mode):
        self.p = self.pop()

    def _branch(self, taken):
        off = self.mem[self.pc]
        self.pc = (self.pc + 1) & 0xFFFF
        if not taken:
            return
        if off & 0x80:
            off -= 0x100
        dst = (self.pc + off) & 0xFFFF
        self.cycles += 2 if (dst & 0xFF00) != (self.pc & 0xFF00) else 1
        self.pc = dst

    def _op_BCC(self, mode):
        self._branch(not self.c)

    def _op_BCS(self, mode):
        self._branch(bool(self.c))

    def _op_BEQ(self, mode):
        self._branch(bool(self.z))

    def _op_BNE(self, mode):
        self._branch(not self.z)

    def _op_BMI(self, mode):
        self._branch(bool(self.n))

    def _op_BPL(self, mode):
        self._branch(not self.n)

    def _op_BVS(self, mode):
        self._branch(bool(self.v))

    def _op_BVC(self, mode):
        self._branch(not self.v)

    def _op_JMP(self, mode):
        self.pc = self._addr(mode, penalise=False)

    def _op_JSR(self, mode):
        target = self._addr(ABS, penalise=False)
        ret = (self.pc - 1) & 0xFFFF
        self.push((ret >> 8) & 0xFF)
        self.push(ret & 0xFF)
        self.pc = target

    def _op_RTS(self, mode):
        lo = self.pop()
        hi = self.pop()
        self.pc = ((lo | (hi << 8)) + 1) & 0xFFFF

    def _op_RTI(self, mode):
        self.p = self.pop()
        lo = self.pop()
        hi = self.pop()
        self.pc = lo | (hi << 8)

    def _op_BRK(self, mode):
        raise UnknownOpcode(0x00, (self.pc - 1) & 0xFFFF)

    def _op_NOP(self, mode):
        pass

    def _op_CLC(self, mode):
        self.c = 0

    def _op_SEC(self, mode):
        self.c = 1

    def _op_CLI(self, mode):
        self.i = 0

    def _op_SEI(self, mode):
        self.i = 1

    def _op_CLV(self, mode):
        self.v = 0

    def _op_CLD(self, mode):
        self.d = 0

    def _op_SED(self, mode):
        raise NotImplementedError(
            f"SED at ${(self.pc - 1) & 0xFFFF:04X}: decimal mode is not "
            "modelled and nothing in this codebase uses it")
