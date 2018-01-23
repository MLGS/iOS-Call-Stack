## iOS中线程Call Stack的捕获和解析
<本文来自于:[iOS中线程Call Stack的捕获和解析（一）](http://blog.csdn.net/jasonblog/article/details/49909163) [iOS中线程Call Stack的捕获和解析（二）](http://blog.csdn.net/jasonblog/article/details/49909209)>
- ### 一、获取任意一个线程的 Call Stack
获取当前线程的调用栈API:

``` objective-c
[NSThread callStackSymbols]
```
但是获取任意线程的调用栈没有相关API, 所以的自己编码实现
- #### 1. 基础结构
线程调用栈图
<br> ![调用栈](https://github.com/MLGS/iOS-Call-Stack/blob/master/%E8%B0%83%E7%94%A8%E6%A0%88.png) </br>
> 每一级的方法调用, 都对应了一张活动记录表, 也称为活动帧. 也就是说, 调用栈是由一张张帧结构组成的, 可以称之为栈帧
我们刻印看到一张栈帧结构中包含着Return Address, 也就是当前活动记录执行结束后要返回的地址.
那么在我们获取到栈帧后, 就可以通过返回地址来进行回溯了.

- #### 2. 指令指针和基址指针
> 我们明确了两个目标:(1)当前执行的指令, (2)当前栈帧结构
以x86为例, 寄存器用途如下:

```
SP/ESP/RSP: Stack pointer for top address of thee stack.
BP/EBP/RBP: Stack pointer for holding thee address of the current stack frame.
IP/EIP/RIP: Instruction pointer. Holds the program counter, thee curreent instruction address
```
> 可以看到, 我们可以通过指令来获取当前指令地址, 以及通过栈基址获取当前栈帧地址. 那么怎么获取到相关寄存器呢?

- #### 3. 线程执行状态
> 考虑到一个线程被挂起时, 后继续执行需要恢复现场, 所以在挂起时相关现场需要被保存起来, 比如当前执行到哪条指令了. 那么就要相关的结构体来为线程保存运行时的状态, 经过一番查询, 得到如下信息:

> The function thread_get_state returns the exection state (e.g. the machine registers) of target_thread as specified by flavor.

```
Function - Return the execution state for a thread.

SYNOPSIS

kern_return_t   thread_get_state
(thread_act_t                   target_thread,
thread_state_flavor_t                 flavor,
thread_state_t                     old_state,
mach_msg_type_number_t       old_state_count)
/*
* THREEAD_SATE_FLAVOR_LIST 0
* these aree the supported flavors
*/
#define x86_THREAD_STATE32      1
#define x86_FLOAT_STATE32       2
#define x86_EXCEPTION_STATE32       3
#define x86_THREAD_STATE64      4
#define x86_FLOAT_STATE64       5
#define x86_EXCEPTION_STATE64       6
#define x86_THREAD_STATE        7
#define x86_FLOAT_STATE         8
#define x86_EXCEPTION_STATE     9
#define x86_DEBUG_STATE32       10
#define x86_DEBUG_STATE64       11
#define x86_DEBUG_STATE         12
#define THREAD_STATE_NONE       13
/* 14 and 15 are used for the internal x86_SAVED_STATE flavours */
#define x86_AVX_STATE32         16
#define x86_AVX_STATE64         17
#define x86_AVX_STATE           18
```
> 所以我们可以通过这个API搭配相关参数来获得想要的寄存器信息:

``` objective-c
bool jdy_fillThreadStateIntoMachineContext(thread_t thread, _STRUCT_MCONTEXT *machineContext) {
mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
kern_return_t kr = thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&machineContext->__ss, &state_count);
return (kr == KERN_SUCCESS);
}
```
> 这里引入了一个结构体叫 ``` _STRUCT_MCONTEXT```.

- #### 4. 不同平台的寄存器
> ``` _STRUCT_MCONTEXT```在不同平台上的结构不同:
<br> x86_64, 如iPhone 6模拟器: </br>

```
_STRUCT_MCONTEXT64
{
_STRUCT_X86_EXCEPTION_STATE64   __es;
_STRUCT_X86_THREAD_STATE64  __ss;
_STRUCT_X86_FLOAT_STATE64   __fs;
};

_STRUCT_X86_THREAD_STATE64
{
__uint64_t  __rax;
__uint64_t  __rbx;
__uint64_t  __rcx;
__uint64_t  __rdx;
__uint64_t  __rdi;
__uint64_t  __rsi;
__uint64_t  __rbp;
__uint64_t  __rsp;
__uint64_t  __r8;
__uint64_t  __r9;
__uint64_t  __r10;
__uint64_t  __r11;
__uint64_t  __r12;
__uint64_t  __r13;
__uint64_t  __r14;
__uint64_t  __r15;
__uint64_t  __rip;
__uint64_t  __rflags;
__uint64_t  __cs;
__uint64_t  __fs;
__uint64_t  __gs;
};
```
> x86_32, 如iPhone 4s模拟器:

```
_STRUCT_MCONTEXT32
{
_STRUCT_X86_EXCEPTION_STATE32   __es;
_STRUCT_X86_THREAD_STATE32  __ss;
_STRUCT_X86_FLOAT_STATE32   __fs;
};

_STRUCT_X86_THREAD_STATE32
{
unsigned int    __eax;
unsigned int    __ebx;
unsigned int    __ecx;
unsigned int    __edx;
unsigned int    __edi;
unsigned int    __esi;
unsigned int    __ebp;
unsigned int    __esp;
unsigned int    __ss;
unsigned int    __eflags;
unsigned int    __eip;
unsigned int    __cs;
unsigned int    __ds;
unsigned int    __es;
unsigned int    __fs;
unsigned int    __gs;
};
```
> ARM64, 如iPhone 5s:

```
_STRUCT_MCONTEXT64
{
_STRUCT_ARM_EXCEPTION_STATE64   __es;
_STRUCT_ARM_THREAD_STATE64  __ss;
_STRUCT_ARM_NEON_STATE64    __ns;
};

_STRUCT_ARM_THREAD_STATE64
{
__uint64_t    __x[29];  /* General purpose registers x0-x28 */
__uint64_t    __fp;     /* Frame pointer x29 */
__uint64_t    __lr;     /* Link register x30 */
__uint64_t    __sp;     /* Stack pointer x31 */
__uint64_t    __pc;     /* Program counter */
__uint32_t    __cpsr;   /* Current program status register */
__uint32_t    __pad;    /* Same size for 32-bit or 64-bit clients */
};
```
> ARMv7/v6, 如iPhone 4s:

```
_STRUCT_MCONTEXT32
{
_STRUCT_ARM_EXCEPTION_STATE __es;
_STRUCT_ARM_THREAD_STATE    __ss;
_STRUCT_ARM_VFP_STATE       __fs;
};

_STRUCT_ARM_THREAD_STATE
{
__uint32_t  __r[13];    /* General purpose register r0-r12 */
__uint32_t  __sp;       /* Stack pointer r13 */
__uint32_t  __lr;       /* Link register r14 */
__uint32_t  __pc;       /* Program counter r15 */
__uint32_t  __cpsr;     /* Current program status register */
};
```
> 可以对照《iOS ABI Function Call Guide》，其中在ARM64相关章节中描述到：</br>
<br>The frame pointer register (x29) must always address a valid frame record, although some functions–such as leaf functions or tail calls–may elect not to create an entry in this list. As a result, stack traces will always be meaningful, even without debug information</br>
<br>而在ARMv7/v6上描述到：</br>
<br>The function calling conventions used in the ARMv6 environment are the same as those used in the Procedure Call Standard for the ARM Architecture (release 1.07), with the following exceptions:</br>
<br>*The stack is 4-byte aligned at the point of function calls. </br>
<br>Large data types (larger than 4 bytes) are 4-byte aligned. </br>
<br>Register R7 is used as a frame pointer
Register R9 has special usage.*</br>
<br>所以，通过了解以上不同平台的寄存器结构，我们可以编写出比较通用的回溯功能。</br>

- #### 4. 算法实现
```
/**
* 关于栈帧的布局可以参考：
* https://en.wikipedia.org/wiki/Call_stack
* http://www.cs.cornell.edu/courses/cs412/2008sp/lectures/lec20.pdf
* http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/
*/
typedef struct JDYStackFrame {
const struct JDYStackFrame* const previous;
const uintptr_t returnAddress;
} JDYStackFrame;

//

int jdy_backtraceThread(thread_t thread, uintptr_t *backtraceBuffer, int limit) {
if (limit <= 0) return 0;

_STRUCT_MCONTEXT mcontext;
if (!jdy_fillThreadStateIntoMachineContext(thread, &mcontext)) {
return 0;
}

int i = 0;
uintptr_t pc = jdy_programCounterOfMachineContext(&mcontext);
backtraceBuffer[i++] = pc;
if (i == limit) return i;

uintptr_t lr = jdy_linkRegisterOfMachineContext(&mcontext);
if (lr != 0) {
/* 由于lr保存的也是返回地址，所以在lr有效时，应该会产生重复的地址项 */
backtraceBuffer[i++] = lr;
if (i == limit) return i;
}

JDYStackFrame frame = {0};
uintptr_t fp = jdy_framePointerOfMachineContext(&mcontext);
if (fp == 0 || jdy_copyMemory((void *)fp, &frame, sizeof(frame)) != KERN_SUCCESS) {
return i;
}

while (i < limit) {
backtraceBuffer[i++] = frame.returnAddress;
if (frame.returnAddress == 0
|| frame.previous == NULL
|| jdy_copyMemory((void *)frame.previous, &frame, sizeof(frame)) != KERN_SUCCESS) {
break;
}
}

return i;
}
```
- ### 二、编码实现对一个地址进行符号化解析
- #### 1. 部分参考资料
> 做这一块时也是查阅了很多链接和书籍，包括但不限于：
<br> 1. [《OS X ABI Mach-O File Format Reference》](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/)
<br> 2. [《Mach-O Programming Topics》](https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html)
<br> 3. [《程序员的自我修养》](https://book.douban.com/subject/3652388/)
<br> 4. [《The Mac Hacker’s Handbook》](https://www.amazon.cn/The-Mac-Hacker-s-Handbook-Miller-Charles/dp/0470395362/ref=sr_1_1?ie=UTF8&qid=1447826833&sr=8-1&keywords=mac+hacker+handbook)
<br> 5. [《Mac OS X and iOS Internals》](https://www.amazon.cn/Mac-OS-X-and-iOS-Internals-To-the-Apple-s-Core-Levin-Jonathan/dp/1118057651/ref=pd_sim_sbs_14_1?ie=UTF8&dpID=51y%2BHC3RdML&dpSrc=sims&preST=_AC_UL160_SR126%2C160_&refRID=0RVDY2AYPWF1ZEY43J5C)

- #### 2. 相关API和数据结构
> 由于我们在上面回溯线程调用栈拿到的是一组地址，所以这里进行符号化的输入输出应该分别是地址和符号，接口设计类似如下：</br>
<br> ```-(NSString*)symbolicateAddress:(uintptr_t)add;```</br>
<br> 不过在实际操作中，我们需要依赖于dyld相关方法和数据结构：

```
/*
* Structure filled in by dladdr().
*/
typedef struct dl_info {
const char      *dli_fname;     /* Pathname of shared object */
void            *dli_fbase;     /* Base address of shared object */
const char      *dli_sname;     /* Name of nearest symbol */
void            *dli_saddr;     /* Address of nearest symbol */
} Dl_info;

extern int dladdr(const void *, Dl_info *);
DESCRIPTION
These routines provide additional introspection of dyld beyond that provided by dlopen() and dladdr()

_dyld_image_count() returns the current number of images mapped in by dyld. Note that using this count
to iterate all images is not thread safe, because another thread may be adding or removing images dur-ing during
ing the iteration.

_dyld_get_image_header() returns a pointer to the mach header of the image indexed by image_index.  If
image_index is out of range, NULL is returned.

_dyld_get_image_vmaddr_slide() returns the virtural memory address slide amount of the image indexed by
image_index. If image_index is out of range zero is returned.

_dyld_get_image_name() returns the name of the image indexed by image_index. The C-string continues to
be owned by dyld and should not deleted.  If image_index is out of range NULL is returned.
```
> 又为了要判断此次解析是否成功，所以接口设计演变为：</br>
<br> ``` bool jdy_symbolicateAddress(const uintptr_t addr, Dl_info *info)```</br>
<br>DI_info用来填充解析的结果.

- #### 3. 算法思路
> 对一个地址进行符号化解析说起来也是比较直接的，就是找到地址所属的内存镜像，然后定位该镜像中的符号表，最后从符号表中匹配目标地址的符号.</br>
![符号表镜像](https://github.com/MLGS/iOS-Call-Stack/blob/master/%E7%AC%A6%E5%8F%B7%E8%A1%A8%E9%95%9C%E5%83%8F.gif)(图片来源于苹果官方文档)</br>
<br> 以下思路是描述一个大致的方向，并没有涵盖具体的细节，比如基于ASLR的偏移量：

```
// 基于ASLR的偏移量https://en.wikipedia.org/wiki/Address_space_layout_randomization

/**

* When the dynamic linker loads an image,

* the image must be mapped into the virtual address space of the process at an unoccupied address.

* The dynamic linker accomplishes this by adding a value "the virtual memory slide amount" to the base address of the image.

*/
```
- ##### 3.1 寻找包含地址的目标镜像
> 起初看到一个API还有点小惊喜，可惜iPhone上用不了：</br>
``` extern bool _dyld_image_containing_address(const void* address)```
</br> ``` __OSX_AVAILABLE_BUT_DEPRECATED(__MAC_10_3,__MAC_10_5,__IPHONE_NA,__IPHONE_NA);```</br>
<br> 所以得自己来判断。
<br> 怎么判断呢？</br>
<br> A segment defines a range of bytes in a Mach-O file and the addresses and memory protection attributes at which those bytes are mapped into virtual memory when the dynamic linker loads the application. As such, segments are always virtual memory page aligned. A segment contains zero or more sections.</br>
<br> 通过遍历每个段，判断目标地址是否落在该段包含的范围内：

```
/*
* The segment load command indicates that a part of this file is to be
* mapped into the task's address space.  The size of this segment in memory,
* vmsize, maybe equal to or larger than the amount to map from this file,
* filesize.  The file is mapped starting at fileoff to the beginning of
* the segment in memory, vmaddr.  The rest of the memory of the segment,
* if any, is allocated zero fill on demand.  The segment's maximum virtual
* memory protection and initial virtual memory protection are specified
* by the maxprot and initprot fields.  If the segment has sections then the
* section structures directly follow the segment command and their size is
* reflected in cmdsize.
*/
struct segment_command { /* for 32-bit architectures */
uint32_t    cmd;        /* LC_SEGMENT */
uint32_t    cmdsize;    /* includes sizeof section structs */
char        segname[16];    /* segment name */
uint32_t    vmaddr;     /* memory address of this segment */
uint32_t    vmsize;     /* memory size of this segment */
uint32_t    fileoff;    /* file offset of this segment */
uint32_t    filesize;   /* amount to map from the file */
vm_prot_t   maxprot;    /* maximum VM protection */
vm_prot_t   initprot;   /* initial VM protection */
uint32_t    nsects;     /* number of sections in segment */
uint32_t    flags;      /* flags */
};


/**
* @brief 判断某个segment_command是否包含addr这个地址，基于segment的虚拟地址和段大小来判断
*/
bool jdy_segmentContainsAddress(const struct load_command *cmdPtr, const uintptr_t addr) {
if (cmdPtr->cmd == LC_SEGMENT) {
struct segment_command *segPtr = (struct segment_command *)cmdPtr;
if (addr >= segPtr->vmaddr && addr < (segPtr->vmaddr + segPtr->vmsize)) {
return true;
}
}

return false;
}
```
> 这样一来，我们就可以找到包含目标地址的镜像文件了。

- ##### 3.2 定位目标镜像的符号表
> 由于符号的收集和符号表的创建贯穿着编译和链接阶段，这里就不展开了，而是只要确定除了代码段_TEXT和数据段DATA外，还有个_LINKEDIT段包含符号表：</br>
<br> ``` The __LINKEDIT segment contains raw data used by the dynamic linker, such as symbol, string, and relocation table entries.```</br>
<br> 所以现在我们需要先定位到__LINKEDIT段，同样摘自苹果官方文档：</br>
<br> ``` Segments and sections are normally accessed by name. Segments, by convention, are named using all uppercase letters preceded by two underscores (for example, _TEXT); sections should be named using all lowercase letters preceded by two underscores (for example, _text). This naming convention is standard, although not required for the tools to operate correctly.```</br>
<br> 我们通过遍历每个段，比较段名称是否和__LINKEDIT相同：</br>

```
usr/include/mach-o/loader.h
#define SEG_LINKEDIT    "__LINKEDIT"
```
> 接着来找符号表：

```
/*
* 摘自《The Mac Hacker's Handbook》：
* The LC_SYMTAB load command describes where to find the string and symbol tables within the __LINKEDIT segment. The offsets given are file offsets, so you subtract the file offset of the __LINKEDIT segment to obtain the virtual memory offset of the string and symbol tables. Adding the virtual memory offset to the virtual-memory address where the __LINKEDIT segment is loaded will give you the in-memory location of the string and sym- bol tables.
*/
```
> 也就是说，我们需要结合__LINKEDIT segment_command（见上面结构描述）和LC_SYMTAB load_command（见下面结构描述）来定位符号表：

```
/*
* The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
* "stab" style symbol table information as described in the header files
* <nlist.h> and <stab.h>.
*/
struct symtab_command {
uint32_t    cmd;        /* LC_SYMTAB */
uint32_t    cmdsize;    /* sizeof(struct symtab_command) */
uint32_t    symoff;     /* symbol table offset */
uint32_t    nsyms;      /* number of symbol table entries */
uint32_t    stroff;     /* string table offset */
uint32_t    strsize;    /* string table size in bytes */
};
```
> 如上述引用描述，LC_SYMTAB和_LINKEDIT中的偏移量都是文件偏移量，所以要获得内存中符号表和字符串表的地址，我们先将LC_SYMTAB的symoff和stroff分别减去LINKEDIT的fileoff得到虚拟地址偏移量，然后再加上_LINKEDIT的vmoffset得到虚拟地址。当然，要得到最终的实际内存地址，还需要加上基于ASLR的偏移量。

- ##### 3.3 在符号表中寻找和目标地址最匹配的符号
> 终于找到符号表了，写到这里有点小累，直接贴下代码：

```
/**
* @brief 在指定的符号表中为地址匹配最合适的符号，这里的地址需要减去vmaddr_slide
*/
const JDY_SymbolTableEntry *jdy_findBestMatchSymbolForAddress(uintptr_t addr,
JDY_SymbolTableEntry *symbolTable,
uint32_t nsyms) {

// 1. addr >= symbol.value; 因为addr是某个函数中的一条指令地址，它应该大于等于这个函数的入口地址，也就是对应符号的值；
// 2. symbol.value is nearest to addr; 离指令地址addr更近的函数入口地址，才是更准确的匹配项；

const JDY_SymbolTableEntry *nearestSymbol = NULL;
uintptr_t currentDistance = UINT32_MAX;

for (uint32_t symIndex = 0; symIndex < nsyms; symIndex++) {
uintptr_t symbolValue = symbolTable[symIndex].n_value;
if (symbolValue > 0) {
uintptr_t symbolDistance = addr - symbolValue;
if (symbolValue <= addr && symbolDistance <= currentDistance) {
currentDistance = symbolDistance;
nearestSymbol = symbolTable + symIndex;
}
}
}

return nearestSymbol;
}


/*
* This is the symbol table entry structure for 64-bit architectures.
*/
struct nlist_64 {
union {
uint32_t  n_strx; /* index into the string table */
} n_un;
uint8_t n_type;        /* type flag, see below */
uint8_t n_sect;        /* section number or NO_SECT */
uint16_t n_desc;       /* see <mach-o/stab.h> */
uint64_t n_value;      /* value of this symbol (or stab offset) */
};
```
> 找到匹配的nlist结构后，我们可以通过.n_un.n_strx来定位字符串表中相应的符号名。

