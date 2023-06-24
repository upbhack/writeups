# Writeup Polyshell from Midnightsun CTF 2019 (Quals)

Description:

```nohightlight
You might be cool, but are you 5 popped shells cool?
Service: nc polyshell-01.play.midnightsunctf.se 30000
Hint: The syscalls should be made using standard Linux syscall calling convention
```

After connecting, we obtain the following task:

```nohightlight
Welcome to the polyglot challenge!
Your task is to create a shellcode that can run on the following architectures:
x86
x86-64
ARM
ARM64
MIPS-LE

The shellcode must run within 1 second(s) and may run for at most 100000 cycles.
The code must perform a syscall on each platform according to the following paramters:
Syscall number: 72
Argument 1: 23560
Argument 2: A pointer to the string "summer"

You submit your code as a hex encoded string of max 4096 characters (2048 bytes)

Your shellcode: 
```

Note that the sycall number and arguments vary for each invocation, but the basic structure remains the same,
i.e., we need to generate a shellcode that runs on x86, x86-64, ARM, ARM64 and MIPS-LE, and performs a syscall with an integer and a pointer to a string as arguments.

## Calling Conventions

Due to my inexperience, I started writing shellcodes by hand before remembering that pwntools can generate them automatically.
Therefore, I first looked up the calling conventions:

```nohighlight
Arch/ABI    Instruction           System  Ret  Ret  Error
                                  call #  val  val2
-------------------------------------------------------
arm/EABI    swi 0x0               r7      r0   r1   -     # that instruction does not seem to exist, I used "svc 0" instead.
arm64       svc #0                x8      x0   x1   -
i386        int $0x80             eax     eax  edx  -
mips        syscall               v0      v0   v1   a3       
x86-64      syscall               rax     rax  rdx  -       

Arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7
-------------------------------------------------------
arm/EABI      r0    r1    r2    r3    r4    r5    r6
arm64         x0    x1    x2    x3    x4    x5    -
i386          ebx   ecx   edx   esi   edi   ebp   -
mips/n32,64   a0    a1    a2    a3    a4    a5    -
x86-64        rdi   rsi   rdx   r10   r8    r9    -
```

## Local Testing

I used unicorn to test my shellcodes (other architectures analogously):

```python
def run_x86(code):
    code_len = len(code)
    code_addr = 0x1000
    mem_sz = 0x1000
    stack_addr = 0x10000
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    def hook_syscall(mu, intno, user_data):
        eax = mu.reg_read(UC_X86_REG_EAX)
        ebx = mu.reg_read(UC_X86_REG_EBX)
        ecx = mu.reg_read(UC_X86_REG_ECX)
        print "int 0x80 {} {} {:x}".format(eax, ebx, ecx)
        print mu.mem_read(ecx, 16)

    mu.hook_add(UC_HOOK_INTR, hook_syscall)

    mu.mem_map(code_addr, mem_sz)
    mu.mem_write(code_addr, code)

    mu.mem_map(stack_addr-mem_sz, stack_addr+mem_sz)
    mu.reg_write(UC_X86_REG_ESP, stack_addr)

    mu.emu_start(code_addr, code_addr + code_len)
```

## Individual Shellcodes

```python
# Compiler calls
def rasm_x86(code):
    return unhex(process(["rasm2", "-a", "x86", "-b", "32", code]).readline())
def rasm_x86_64(code):
    return unhex(process(["rasm2", "-a", "x86", "-b", "64", code]).readline())
def rasm_arm(code):
    return unhex(process(["rasm2", "-a", "arm", "-b", "32", code]).readline())
def rasm_arm64(code):
    return unhex(process(["rasm2", "-a", "arm", "-b", "64", code]).readline())

# push string onto stack (i assume a length < 8, which mostly holds)
def make_shellcode_x86(syscall, arg1, arg2):
    return rasm_x86("""
    mov eax, {syscall}
    mov ebx, {arg1}
    push {arg2_2}
    push {arg2_1}
    mov ecx, esp
    int 0x80
    """.format(syscall=syscall, arg1=arg1,
               arg2_1=u32(arg2[:4]), arg2_2=u32(arg2[4:].ljust(4, '\0'))))

def make_shellcode_x86_64(syscall, arg1, arg2):
    return code = rasm_x86_64("""
    mov rax, {syscall}
    mov rdi, {arg1}
    mov rbx, {arg2}
    push rbx
    mov rsi, rsp
    syscall
    """.format(syscall=syscall, arg1=arg1, arg2=u64(arg2.ljust(8, '\0'))))

# movw only works with 16 bit operands (arg1 is sometimes larger)
def make_shellcode_arm(syscall, arg1, arg2):
    def push_val(v):
        return rasm_arm("movw r0, %d; movt r0, %d; push {r0};" % (v & 0xffff, v >> 16))
    assert arg1 < 2**16
    code = push_val(u32(arg2[4:].ljust(4, '\0')))
    code += push_val(u32(arg2[:4]))
    code += rasm_arm("""
    movw r7, {syscall} 
    movw r0, {arg1}
    mov r1, sp
    svc 0
    """.format(syscall=syscall, arg1=arg1))
    return code

# For some reason (this took me quite a while to figure out), the arm64 shellcode does not seem to have a stack...
# Hence, I append the string to the code and load its address with the "adr" instruction
def make_shellcode_arm64(syscall, arg1, arg2):
    s = "adr x1, 16; movz x8, {syscall}; movz x0, {arg1}; svc 0".format(syscall=syscall,arg1=arg1)
    return rasm_arm64(s) + " " + arg2.ljust(8, "\0")

# Here I remembered the gloriousness that is pwntools
def make_shellcode_mips(syscall, arg1, arg2):
    context.arch = "mips"
    code_mips = asm(shellcraft.pushstr(arg2) +
                    shellcraft.syscall(syscall, arg1, "$sp"))
    return code_mips
```

## Polyglot x86/x86-64

I got this from https://stackoverflow.com/a/50978334:

```nohighlight
get_mode:
        mov eax, 1
        dec eax
        test eax, eax
        ret

In 64-bit mode, dec eax becomes the REX.W prefix for the test instruction.
Thus, this code returns 0 when run in 32-bit mode and returns 1 when run in 64-bit mode.
It also sets Z accordingly, so it can be used from another assembly language function like this:

    call get_mode
    jnz mode64
```

From this I construct the polyglot:

```python
def make_polyglot_x64_x86_64(syscall, arg1, arg2):
    code_x86 = make_shellcode_x86(syscall, arg1, arg2)
    code_x86_64 = make_shellcode_x86_64(syscall, arg1, arg2)
    code = unhex("31c0" + "48" + "90") # xor eax,eax; dec eax; nop; (in x86)
    code += rasm_x86("jz " + str(len(code_x86)+3))
    code += code_x86
    code += 10*"\x90"
    code += code_x86_64
    return code
```

## Polyglot ARM/ARM64

From https://github.com/ixty/xarch_shellcode/tree/master/stage0:

```nohighlight
For the arm / arm64 branching we use:
0xXX 0xXX 0xXX 0xEA
    arm       b       XXX
    arm64     ands    x1, x0, x0

(exact decoded instructions will change based on the offset values)
```

```python
def make_polyglot_arm_arm64(syscall, arg1, arg2):
    code_arm64 = make_shellcode_arm64(syscall, arg1, arg2)
    code_arm = make_shellcode_arm(syscall, arg1, arg2)
    code = unhex("050000ea") # b 0x1c (in ARM)
    code += code_arm64
    code += (4-(len(code)%4))*"?" # align subsequent code to 4 bytes
    code += code_arm
    return code
```

## Polyglot ARM/ARM64/x86/x86-64

From https://github.com/ixty/xarch_shellcode/tree/master/stage0:

```nohighlight
For the x86 / arm branching we use the following:
0xEB 0xXX 0x00 0x32     (with XX being the offset to x86 code)
    arm       andlo   r0, r0, #0xeb000
    arm64     orr     w11, w23, #7
    x86       jmp     $+0xa / junk
    x86_64    jmp     $+0xa / junk
```

```python
def make_polyglot_x86_arm(syscall, arg1, arg2):
    code_arm = make_polyglot_arm_arm64(syscall, arg1, arg2)
    code_x86 = make_polyglot_x64_x86_64(syscall, arg1, arg2)
    code = unhex("eb640032") # jmp 0x66 (in x86)
    code += code_arm
    code = code.ljust(120, "\x90")
    code += code_x86
    return code
```

## Polyglot MIPS/ARM/ARM64/x86/x86-64

Now comes the hard part. My objective was to find a MIPS instruction that performs a jump and is (effectively) a NOP in the other architectures.
Note that MIPS has a branch delay slot, i.e., it executes the instruction after a conditional branch unconditionally.
We are lucky since the first instruction of the previous polyglot `eb640032`  (see `make_polyglot_x86_arm`) is harmless; it decodes to `andi zero, s0, 0x64eb`.

To that end, I went through the MIPS jump instructions and decompiled them in ARM/ARM64 to see if they are a NOP.
Note that in both ARM and MIPS, the byte determining the instruction is the fourth byte, while the first byte is used in x86.
So for a jump, we can play around with the offset to find one that makes the instruction NOP(s) in x86.

The one that finally worked for me was `beq a3, a3, 0x39c`.
To find an offset that works, I used a script:

```python
for i in range(256): # the jump will be over i instructions or 4*i bytes
    c = "rasm2 -a x86 -b 32 -d {:02x}00e710".format(i)
    print c
    os.system(c)
```

I chose `e600e710`.

```nohighlight
ARM:    rscne r0, r7, r6, ror 1    (Conditional Reverse Subtract with Carry)
ARM64:  adr x6, 0xfffffffffffce01c (Load address relative to PC)
x86/64: out 0, al; out 0x10, eax   (Output byte in AL to I/O port address imm8)
MIPS:   beq a3, a3, 0x39c
```

```python
def make_polyglot(syscall, arg1, arg2):
    # fill with sufficiently many NOPs since I am too lazy to calculate the actual offset
    code = (unhex("e600e710") + make_polyglot_x86_arm(syscall, arg1, arg2)).ljust(1600, "\0")\
           + make_shellcode_mips(syscall, arg1, arg2)
    return code
```