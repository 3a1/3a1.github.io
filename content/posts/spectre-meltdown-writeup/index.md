---
title: "Performance over security: Speculative execution vulnerabilities (Spectre & Meltdown)"
draft: false
date: 2026-05-09T10:13:20.000Z
description: "A deep dive into Spectre and Meltdown, two hardware-level vulnerabilities that traded security for performance."
---

**Small note**

Hi, it's been almost a year since my last post. I'm back. Let's get into it.<br>
Recently, I've been going down a rabbit hole on speculative execution vulnerabilities, and the deeper I went, the more fascinating it became.
So I decided to put it all together in one writeup, two hardware-level flaws disclosed in 2018 that are still relevant today. <br>
Some parts extend just Spectre and Meltdown scope, but decided to leave them without change.
Writeup is made for people that are not familiar with those vulnerabilities, if you are, then you will likely won't find anything new. <br>
Hope you find them as fascinating as I did.

## 1. Instruction-Level Parallelism (ILP)

Let’s move to the 20th century, when the first digital computers were created. Early computers used scalar processors, a class that implement single instruction, single data (SISD) architecture.

Each instruction in the CPU goes through three main stages. These stages are Fetch, Decode, and Execute. Scalar processors execute one instruction per clock cycle (CLK). 

To better understand how they work, it’s useful to use a diagram.

<img src="SpeculativeExecutionVulnsWriteup-Page-1.drawio.svg" 
     style="width:50%; max-width:750px; display:block; margin:0 auto;" />

### 1.1 Instruction Pipelining

As shown in the illustration, each clock cycle performs one operation at a time. This is how computers worked until the IBM Stretch (7030) was introduced in 1961. This computer used a technique called advanced overlapping instruction execution, now known as pipelining. 

Pipelining is a concept where the CPU can handle multiple operations within a single clock cycle. This works because the CPU has separate hardware units for Fetch, Decode, and Execute stages. In a single clock cycle, it can fetch one instruction, decode another, and execute a third. 

If we represent the original execution diagram with pipelining, it looks like this:

<img src="SpeculativeExecutionVulnsWriteup-Page-2.drawio.svg" 
     style="width:50%; max-width:750px; display:block; margin:0 auto;" />

At each clock cycle, the CPU executes the previously decoded instruction, decodes the previously fetched instruction and fetches a new instruction if there is one. It looks like a waterfall, doesn’t it? This is why it is sometimes referred to as "waterfall execution". 

Pipelining can increase performance by up to 3x. Without pipelining, each instruction requires 3 clock cycles. For 10 instructions, this results in 10 x 3 = 30 cycles. With pipelining, the first instruction requires 3 cycles before it completes, and each subsequent instruction completes in one clock cycle. As a result, 10 instructions take 3 + (10 − 1) = 12 cycles.

### 1.2 Superscalar Execution

With pipelining, performance improves significantly. However, as long as there is only one fetch, decode, and execute unit, the CPU can execute at most one instruction per clock cycle. This was the limit until the CDC 6600 was introduced in 1964. This computer used the first superscalar processor. 

This processor used multiple functional units that could operate in parallel. This is known as superscalar execution. If we add superscalar execution to the previous pipelined model, it looks like this:

<img src="SpeculativeExecutionVulnsWriteup-Page-3.drawio.svg" 
     style="width:90%; max-width:750px; display:block; margin:0 auto;" />

As shown in the diagram, since there are now two units for each stage (Fetch, Decode, and Execute), the CPU can now execute up to two instructions per clock cycle. 

What if the second instruction depends on the result of the previous one?

This is where hazard detection comes in. It is a unit that analyzes instructions to determine whether they can execute in parallel. If instructions operate on different registers, they can run in parallel. If two instructions use the same register, hazard detection ensures that execution remains correct and preserves the proper order.

### 1.3 Out-of-Order Execution

As we have now introduced superscalar pipelining, we can execute two parallel instructions at the same time. How can we optimize it further? Let’s say we have this instruction set:

```nasm
mov rax, [Memory] ; 100 cycles
add rax, rax      ; 1 cycle
mov rcx, [Memory] ; 100 cycles
add rcx, rcx      ; 1 cycle
```

What happens if we try to run this on our current CPU?
Our CPU can handle only two instructions per cycle. However, because the second instruction depends on the result of the first one, the CPU will wait 100 cycles for the memory operation to complete. Then it proceeds with the remaining instructions. In total, this takes 202 clock cycles.

But what if we reorder the instructions?

```nasm
mov rax, [Memory] ; 100 cycles
mov rcx, [Memory] ; 100 cycles
add rax, rax      ; 1 cycle
add rcx, rcx      ; 1 cycle
```

Now we can read in parallel two instructions with memory reading because they do not create a data hazard, then we can execute the arithmetic operations in parallel as well. In total, this takes 101 cycles to finish, twice as fast than without reordering instructions. 

This technique is known as Out-of-Order execution (OoO). Modern processors use a dedicated Out-of-Order execution engine which also uses register allocation, register renaming and retiring but we will skip those parts here.

You may ask: doesn’t this break the original program execution order?
Answer is no. Instructions are executed out of order, but their results are stored in a Reorder Buffer (ROB), which ensures they are committed in the original program order.

### 1.4 Speculative Execution

Can we further optimize our CPU? Let’s say we have this loop:

```nasm
start:
	xor rax, rax
check:
  inc rax
  cmp rax, 100
	jl check
	ret
```

This loop initializes RAX to zero, then increments it until it reaches 100, and then returns. The main loop consists of three instructions: INC, CMP, and JL.

The CPU may stall on the CMP instruction, because the CPU does not know whether it should take the branch or not and must wait for the comparison to complete.

If we observe the loop, in 99 out of 100 iterations the branch is taken. This raises the question: What if the CPU predicts that the branch will be taken and continues execution speculatively instead of waiting for the CMP result?

That’s what Speculative Execution is; a technique used by CPUs alongside branch predictor to predict control flow and improve performance.

Speculative execution uses mechanisms that store the architectural state before the branch is resolved. The CPU then executes instructions speculatively. If the prediction is correct, the results are committed. If the prediction is incorrect, the CPU flushes the pipeline and rolls back the architectural state.

In this example, the CMP instruction introduces a 1 cycle stall per iteration, but, if we speculate that this branch will be true, we gain 1 cycle per iteration. In the final iteration, the speculation will be incorrect, which triggers a pipeline flush, that costs around 15 cycles and is expensive, but we have already a gain of around 99 cycles during this loop resulting in an overall improvement of about 84 cycles.

In reality, branch predictor does not only predict whether a branch will be taken or not, it also predicts where to jump. This is done using a structure called the Branch Target Buffer (BTB), which stores previously seen branch targets. When a branch is predicted as taken, the CPU can immediately continue execution from the predicted target address without waiting for the actual computation.

## 2. Price of Performance: Spectre & Meltdown

Any optimization comes with a cost. ILP techniques are no exception. 

Parallel execution of operations that are not designed to execute in parallel results in race conditions. Execution out of original order results in a divergence between architectural and microarchitectural state, where “should not have happened” and “physically did happen” differ.

Speculative execution is the most aggressive ILP technique, so it is no surprise that it introduced serious security problems. There were no widely known vulnerabilities until 2018, when the Spectre and Meltdown papers were published. 

An interesting fact is that, upon their release, security researchers initially believed the reports to be false.

---

### 2.1 Spectre Breakdown

Let’s start from Spectre vulnerability. This vulnerability exploits the fact that during speculative execution the CPU may load data into cache and unlike registers, the cache is not reverted when speculation is rolled back. 

To understand this, we first need to explain how cache works.

#### Cache

In early systems (1960s), CPU speed and memory speed were roughly comparable. There was no significant performance gap between them.

By the 1980s, CPU speed had started accelerating much faster than RAM. Engineers observed that the CPU was spending most of its time waiting for data to be fetched from RAM. This problem became known as the “memory wall”.

Engineers realized that CPUs needed a small, fast memory to store frequently accessed data (e.g., global variables), faster than RAM memory. They introduced a small, fast memory located directly on the CPU die, called cache. 

Modern CPUs use a three-level cache hierarchy. Fastest Layer 1 (L1), Less-Fast Layer 2 (L2) and Slowest Layer 3 (L3). L1 and L2 are private to each core, while L3 is shared across all cores.

The diagram below shows how it on illustration:

<img src="SpeculativeExecutionVulnsWriteup-Page-4.drawio.svg" 
     style="width:75%; max-width:750px; display:block; margin:0 auto;" />

When you are accessing one byte variable in memory, the cache fetches 64 bytes of this address instead and stores it in L1, L2 and L3 layers. 

You might wonder why the CPU fetches 64 bytes when only a single byte is accessed?
This is due to spatial locality, it is a principle that if you are accessing some data, probably you will access other data around. A cache line size of 64 bytes is a common design choice. If the cache line were larger, more unnecessary data would be loaded. If it were smaller, cache misses would occur more frequently. 

You might wonder why CPU stores bytes of data on all cache layers instead of one?
This cache design is called inclusive cache. It’s policy agreement between cache layers that during load the same data will be loaded at every cache layer. 

Because L1 is small, over time it will overwrite cache line containing this data with new data. If the same memory is accessed again, it will instead be fetched from L2 because it’s larger and still contains this cache line. 

Now let’s look at the cache structure:

<img src="SpeculativeExecutionVulnsWriteup-Page-5.svg" 
     style="width:100%; max-width:750px; display:block; margin:0 auto;" />

A cache stores data in an array of cache lines (CL), where each line contains 64 bytes. These cache lines are grouped into sets, with each set containing 8 ways. 
In simple terms it’s essentially a 2D table, sets as rows and ways as columns, where each cell holds 64 bytes of data. In total, there are 64 sets with 8 ways each, resulting in 64 × 8 = 512 cache lines (512 × 64 bytes = 32 KB). 
The same concept applies to L2 and L3 caches. The structure is similar, with the main differences being size (number of sets) and speed.

#### Tag Array

If we are reading some data that has been previously saved in cache, the CPU does not sequentially search through all cache levels. Each cache level contains a structure called the Tag Array. 
It’s an array that contains information about each cache line cell. 
The CPU checks the Tag Array first; if the tag matches, it fetches the data directly from that cache layer without searching further. 
Which means the CPU can detect a cache miss by checking only the Tag Array, without touching the data array at all.

In many sources cache is shown as a structure where cache line data and cache line tag are located together, that’s not true. Logically that’s how CPU is accessing it, first the tag then associated data but they are located in different arrays.

<img src="SpeculativeExecutionVulnsWriteup-Page-11.drawio.svg" 
     style="width:40%; max-width:750px; display:block; margin:0 auto;" />

To look up data, the CPU splits the RAM address into three fields: tag, index, and offset which tell it exactly which set to check in tag array and then which bytes to read in data array. This is what allows cache lookups to be nearly instant.

<img src="SpeculativeExecutionVulnsWriteup-Page-7.drawio.svg" 
     style="width:40%; max-width:750px; display:block; margin:0 auto;" />

Tag Array structure is similar to cache, same sets of ways, the only difference is the size of each cell, it’s only 22 bits instead of 64 bytes in cache. Each cell holds Tag Entry (TE) that describes information about its corresponding cache line. The CPU only needs to access a compact array of 22 bit entries rather than the full 32 KB data array to determine is there cache hit or miss.

#### Speculative Execution Core Problem

We now know how Speculative Execution and CPU Cache work, both designed to squeeze maximum performance out of modern CPUs. Unfortunately, they were never designed with security in mind when used together, and that's exactly where the vulnerability comes from.

Let's go back to our speculative execution example. When the branch predictor is wrong, the CPU reverts its state back to where it was before the speculation began, registers, program counter, everything rolls back cleanly.

Now let’s add cache into the picture. During speculative execution, the CPU may read data from RAM, and the cache silently stores that data. Then the branch predictor turns out to be wrong, the CPU reverts, but the cache does not.

Why doesn't the CPU revert the cache too? 
Because it would be far too expensive. Rolling back cache state on every misprediction would completely defeat the purpose of speculative execution. The performance gains would vanish entirely.

To make this concrete, let’s look at the following example:

```nasm
	cmp  rcx, 1
	jg  normal_execution
	
	; Speculative execution happens here
	mov rax, [SECRET_VAR]

normal_execution:
	ret
```

Here we have a conditional jump (JG), which is taken if RCX is greater than 1. The branch predictor does not yet know the result of the comparison, so let’s assume it predicts that the branch will not be taken. 

The CPU speculatively continues execution past the branch, moves forward, and reads a secret value from memory into RAX.

Now let's say RCX was actually equal to one, the branch predictor was wrong. The CPU flushes the pipeline back to the state before the jump and resumes execution, this time taking the jump.

But here's the problem. During speculative execution, we accessed data from RAM and the cache silently loaded 64 bytes from that address across every cache level. 

The CPU does everything it can to hide the fact that speculative execution even happened, from a software perspective, you will never observe it. 
But the cache remembers everything.

#### Proof Of Concept

Now that we understand the root cause of this vulnerability, let’s see how secret data can actually be extracted through the cache.

In the previous example, speculative execution accessed a secret value from RAM, causing the CPU to load the corresponding 64-byte cache line into the cache.

From software level, we cannot directly read the CPU cache or inspect individual cache lines. There are no standard instructions that simply reveal cached data. This is where the original Spectre paper introduced a brilliant technique.

First, the attacker creates an array with 256 entries, representing every possible byte value (0–255). Then, each entry is flushed from the cache using the `CLFLUSH` instruction. 

After that, during speculative execution, the CPU reads one byte of the secret and uses that value as an index into the array. Accessing `array[secret_byte]` causes the corresponding cache line to be loaded into the cache.

Once speculative execution is rolled back, the architectural state appears unchanged, but the cache state remains modified. 

The attacker can then measure the access time to every entry in the array. Most entries will take around ~100 cycles to read from memory, while the cached entry corresponding to the secret byte may take only ~10 cycles.

By identifying which array element is accessed significantly faster, the attacker can recover the secret byte.

This can be a bit abstract, so let’s look at how it works in code.

<aside>
💡

Keep in mind that the code shown below is intentionally simplified to make the core idea easier to understand. Some parts are not fully accurate and may require minor adjustments to work in practice.

</aside>

```c
byte_t probe[ 256 * 0x1000 ];
```

First, we create the probe array. In many Spectre PoCs, you will see an array of 256 entries, which makes sense since a byte can have 256 possible values. However, this array is often multiplied by the page size (4096 bytes).

The reason is prefetcher, another speculative feature of the CPU. It can detect access patterns and automatically load nearby data into the cache, which can interfere with our timing measurements and introduce noise.

So how does multiplying by the page size help?
Because the prefetcher does not cross page boundaries. This keeps our measurements clean.

```c
/* Flush probe from cache */
for ( int i = 0; i < 256; i++ )
    _mm_clflush( &probe[ i * 0x1000 ] );
```

First, we flush every probe entry from the cache using the `CLFLUSH` instruction.

This step is important. If even a single entry remains in the cache, it can introduce noise and lead to false positives.

```c
for ( int i = 0; i < 100; i++ )
{
    if ( 1 )
        temp++;
}
```

Now we can try to “train” the branch predictor to keep making the same decision. You can see this step in many Spectre PoCs.

However, in my opinion, this part is not strictly necessary. Modern branch predictors are quite complex, and they may already try to predict multiple possible outcomes internally. Because of that, it’s not entirely clear how much this kind of “manual training” actually helps.

Additionally, the loop itself introduces its own branches at the assembly level, which may interfere with this training and even work against it.

In my testing, the exploit behaves the same even without this step, but it is still commonly included, so it doesn’t hurt to keep it.

```c
if (0)
{
	/* Speculative execution goes here */
    temp += probe[ *(byte_t*)( 0xSECRET ) * 0x1000 ];
}
```

After training the branch predictor (or not), we can create a branch that is normally never executed, but will be executed speculatively.

This code reads a byte from a secret value in memory and uses it as an index into a probe array, accessing a specific entry corresponding to that byte value.

```c
/* Measure timings on access */
for ( int i = 0; i < 256; i++ )
{
    uint64_t start = __rdtscp();

    temp = probe[ i * 0x1000 ];

    uint64_t end = __rdtscp();
    uint64_t access_time = end - start;

    if ( access_time < 80 )
        printf("Fast access at index %d (%llu cycles)\n", i, access_time);
}
```

Now we iterate over all possible byte values and measure the access time for each entry in the probe array.

In this example, we use a fixed threshold (80 cycles). Computers’s CPU are also not identical, cache hit timing that works on AMD Ryzen processors could not work on Intel CPU’s. In practice, it is better to measure cache hit and cache miss timings and derive a threshold dynamically. Alternatively, we can collect all timings and select the fastest access.

Keep in mind that this attack is not deterministic, every run the result could be different. CPU cores can be shared with other threads during execution, which could effect our cache and introduces noise into the results of measuring. 
That’s why we could measure CPU execution on each core and switch to less busy one to decrease noise in the results.
This attack is typically repeated hundreds or thousands of times to statistically reduce noise.

An interesting point is that Spectre can also be exploited using different threads. L1 and L2 caches are private to each core, so one thread can trigger speculative execution while another measures the effect, as long as both run on the same core.

If you carefully read the cache section, modern processors may use an inclusive cache policy, where same cache lines are present across multiple levels. Since the L3 cache is shared between cores, it is theoretically possible to perform the attack across different cores as well.
This is purely theoretical, because the difference between L1 and even L2 cache hits is significant, and it heavily reduces the success rate. However, theoretically, it is still possible.

#### Spectre v1: bounds check bypass

You might wonder, wait, how can this vulnerability actually be exploited?
In the previous example, we speculatively accessed a secret value, but it was within the same address space and the same process. In that case, we could simply dereference the address and read the data directly, so speculative execution does not seem particularly useful at first glance.

That is true, but Spectre can also be exploited using legitimate code in other processes.
Spectre becomes powerful when it allows us to access data that we are not supposed to read, for example, data belonging to another process or a more privileged context.

The original Spectre paper describes two main variants of this attack.
Spectre Variant 1 is based on a technique called bounds check bypass.
Here is an example of vulnerable victim code:

```c
if ( x < array_size )
    y = array[ x ];
```

In this victim code, the attacker needs to control the value of `x` and the base address of the array. In many vulnerable cases, both `x` and the array are derived from pointers or inputs that the attacker can influence.

While Spectre v2 allows exploitation across different processes, Spectre v1 has limitations and is very hard to exploit across processes.

However, let’s consider a scenario where we target the kernel. In this case, we need to find a similar vulnerable code pattern in the kernel, where both `x` and the array depend on user-controlled input, such as system call arguments.

The attacker can invoke a system call and pass a pointer to a secret value they want to read, along with a probe array. If the kernel contains a vulnerable bounds check, it may speculatively execute the access even when `x` is out of bounds.

After the speculation is rolled back, the architectural state remains unchanged, but the cache state is modified. The attacker can then measure access times to the probe array entries to identify which value was accessed, revealing the secret.

#### Spectre v2: BTB poisoning (branch target injection)

Now let’s look at the Spectre second variant. Spectre v2 works differently. Instead of manipulating bounds check, it targets where the CPU will jump.

**Branch Target Buffer Poisoning**

Modern CPUs use previously mentioned structure called the Branch Target Buffer (BTB) to predict the destination of indirect branches (such as function pointers or virtual calls). The BTB stores previously seen branch targets and allows the CPU to continue execution without waiting for the actual target to be resolved.

If an attacker can poison the BTB, they can make the CPU speculatively jump to an attacker-controlled location. Even though this execution is later rolled back, it may still leave observable traces in the cache, just like in Spectre v1.

<img src="SpeculativeExecutionVulnsWriteup-Page-10.drawio.svg" 
     style="width:75%; max-width:750px; display:block; margin:0 auto;" />

The attack could work in the way described below.

First, we need to make sure that our process is running on the same core as the victim process. This is necessary because the BTB (Branch Target Buffer) is shared within the same core.

Next, we need to find a specific Spectre gadget in the victim process.

This gadget could look like this:

```nasm
; Attacker should be able to control R1 (address to read)
; Attacker should be able to control R2 (base of the probe array)
mov rax, [R1]
mov rbx, [R2 + rax * 0x1000]
```

After the Spectre gadget is found, we need to identify a location in the victim process where we want to poison the BTB. This location should contain an indirect branch, for example a simple `jmp [rax]`.

At this branch location, we must be able to control both the memory address being accessed and the base of the probe array through the registers used by our gadget.

BTB entries are associated with the memory addresses of the corresponding branches. This means that to poison a BTB entry, we need to train the same branch at the same address as it exists in the victim process.

In our target process, we should train the branch predictor to associate this branch with the address of the gadget in the victim process. After sufficient training, if everything is done correctly, the victim process executing that branch may speculatively execute our gadget due to the poisoned BTB entry.

During this speculative execution, the attacker can perform the same cache-based data exfiltration technique as in Spectre v1.

To perform this attack against a victim process, we need to control at least two values in registers, which is very difficult to exploit in a real-world environment. You may notice that this attack is actually more reliable when applied across user mode and kernel mode within the same thread.

To perform the same attack in kernel mode, we need to find a similar Spectre gadget. However, we can more easily control registers using a system call.

In `ntoskrnl.exe`, we need to identify functions that could be executed by syscall from usermode and perform indirect jumps from memory. We then poison it’s BTB entry. After that, using a system call, we can pass our data through registers, including the probe array and the secret kernel address that we want to read.

**Spectre Variants Key Differences**

|  | Spectre v1 | Spectre v2 |
| --- | --- | --- |
| Branch type | Conditional (`if`, `jg`) | Indirect (`jmp rax`, vtable call) |
| What is manipulated | Taken / not taken | Jump destination |
| Requires vulnerable code | Bounds check pattern | Any indirect branch |
| Cross-process | No | Yes |

Different versions of spectre just show different exploitation of the same cache attack.

#### Mitigations

After Spectre paper was released several mitigations were introduced.

**Spectre v2**
For Spectre v2, CPU vendors introduced microcode-based mitigations, including **IBRS**, **IBPB**, and **STIBP** on Intel processors.

- **Indirect Branch Restricted Speculation (IBRS)** restricts the use of branch prediction history across privilege boundaries. This prevents user-space branch history from influencing speculation in kernel mode.
- **Indirect Branch Predictor Barrier (IBPB)** flushes indirect branch prediction state during context switches, preventing BTB state from being shared between different processes.
- **Single Thread Indirect Branch Predictors (STIBP)** isolates branch prediction between hyperthreads on SMT systems, reducing cross-thread leakage.

Together, these mitigations significantly reduce the practicality of BTB-based cross-domain attacks.

**Spectre v1**
Spectre v1 is mitigated differently, as it does not rely on branch predictor poisoning but instead exploits speculative execution past bounds checks.

Mitigations are primarily implemented at the compiler and software level.

- **Speculation barriers (`LFENCE`)**
Compilers may insert instructions such as `LFENCE` after bounds checks. This forces the CPU to serialize execution, ensuring that prior conditions are resolved before subsequent memory accesses occur.
- **Index masking**
Instead of relying solely on conditional branches, indices are masked to guarantee they remain within valid bounds, even under speculative execution.

Modern compilers can automatically insert such mitigations in sensitive code paths, particularly when handling untrusted input.

### 2.2 Meltdown Breakdown

Meltdown is a vulnerability that was disclosed alongside Spectre, but it is fundamentally different in how it works.

Unlike Spectre, which relies on manipulating branch prediction, Meltdown exploits a flaw in how CPUs handle memory access permissions during out-of-order execution.

Specifically, Meltdown breaks the isolation between user-space and kernel memory. It allows a user-mode process to read privileged memory that should normally be inaccessible.

Although the CPU eventually detects the illegal access and raises an exception, the data may have already been speculatively loaded and left observable traces in the cache.

This makes it possible to leak sensitive kernel memory from user-space and even escaping VM’s which is pretty insane.

#### Memory Mapping

The first important factor behind this vulnerability is how kernel memory is mapped.

Kernel memory is mapped into every user-mode process, while user-mode memory is not mapped into the kernel in the same way. This design exists mainly for performance reasons. 
When a user-mode thread performs a syscall, it switches to kernel mode. If the kernel memory had to be mapped and unmapped on every transition, it would introduce a significant overhead. To avoid that, the kernel is mapped into every user-mode process from the start.

So a natural question arises: why can’t we just access kernel memory from user mode?
That’s because of memory paging.

<img src="SpeculativeExecutionVulnsWriteup-Page-9.drawio.svg" 
     style="width:100%; max-width:750px; display:block; margin:0 auto;" />

Virtual memory is an abstraction backed by physical memory. When we try to access a virtual address, it must first be translated into a physical address. This translation process is handled by the Memory Management Unit (MMU). To resolve a virtual address, the MMU walks the page tables to find the physical page mapped to that address.

In most systems, virtual address translation involves four levels of page tables: PML4, PDPT, PD, and Page Table (PT).

At the lowest level, the Page Table contains entries called Page Table Entries (PTEs). Each PTE stores information about a physical page, including its address and access permissions.

<img src="SpeculativeExecutionVulnsWriteup-Page-8.drawio.svg" 
     style="width:100%; max-width:750px; display:block; margin:0 auto;" />

A Page Table Entry (PTE) contains 64 bits of information, but for our purposes we will focus on the User/Supervisor (U/S) bit.

This bit defines the access level of the page:

- If the bit is 0, the page is marked as supervisor-only (kernel mode).
- If the bit is 1, the page is accessible from user mode.

When a user-mode thread attempts to access a kernel page, the MMU checks this bit during address translation. If the page is not user-accessible, the CPU raises a fault and the access is blocked.

This is why, even though kernel memory is mapped into the process address space, it cannot be directly accessed from user mode.

Meltdown breaks this guarantee by allowing the CPU to temporally access the data before this permission check is fully enforced.

#### Out-of-Order Execution

The critical factor that makes Meltdown possible is how CPUs handle memory access during out-of-order execution.

On affected Intel processors, the CPU may issue a memory load and continue executing following instructions before the permission check is fully resolved.

In other words, the data can be fetched and temporarily used before the CPU confirms whether the access is allowed.

If the access turns out to be illegal, the CPU raises an exception and rolls back the architectural state. However, any microarchitectural side effects, such as cache state changes, are not reverted.

This allows an attacker to speculatively access privileged data and then extract it using cache side-channel techniques, similar to those used in Spectre.

You may ask, wait, shouldn't Out-of-Order execution still follow the original program order?<br>
Yes, and on most processors, it does.
The problem was specific to Intel.
Their OoO engine was performing permission checks after the memory access had already occurred, allowing speculative execution to use memory value and leave traces in the cache before any violation was ever caught.
The Meltdown paper pointed directly at this as the root cause.

#### Proof Of Concept

```c
byte_t probe[ 256 * 0x1000 ];

/* Flush probe array from cache */
for ( int i = 0; i < 256; i++ )
    _mm_clflush( &probe[ i * 0x1000 ] );

/* Read kernel memory and use the value to touch probe array */
probe[ *(byte_t*)kernel_addr * 0x1000 ] += 1;

/* Measure timings on access */
for ( int i = 0; i < 256; i++ )
{
    uint64_t start = __rdtscp();

    temp = probe[ i * 0x1000 ];

    uint64_t end = __rdtscp();
    uint64_t access_time = end - start;

    if ( access_time < 80 )
        printf("Fast access at index %d (%llu cycles)\n", i, access_time);
}
```

In this example, we use the same probe array technique as before.

We first prepare a probe array and flush it from the cache.

Then comes the key step: we attempt to read a byte from a privileged kernel address and use its value to index into the probe array.

Although this memory access is not allowed and will eventually trigger an exception, the CPU may already speculatively execute the dependent instruction:

```c
probe[ *(byte_t*)kernel_addr * 0x1000 ] += 1;
```

During temporally execution, the kernel value selects a cache line in the probe array. After the exception, we measure access timing to recover the leaked byte from cache side effects.

Unlike Spectre, Meltdown does not rely on branch prediction or training. It directly exploits the fact that memory loads may transiently bypass permission checks.

As a result, an attacker can dump entire kernel memory from user mode, using cache side-channel techniques. 

In some scenarios, this vulnerability could also be used to break isolation between virtual machines, depending on how host memory is mapped.

#### Mitigations

After Meltodown was released there are couple mitigations released too.

KAISER was originally proposed as a mitigation against side-channel attacks targeting kernel address space layout randomization (KASLR). Its main idea was to isolate kernel memory from usermode processes by removing it from their address space.

After the disclosure of Meltdown, it turned out that KAISER also effectively mitigates this vulnerability, since Meltdown relies on the presence of kernel mappings in user space.

KPTI (Kernel Page Table Isolation) is a practical implementation of KAISER idea, adopted by modern operating systems. It separates user and kernel page tables, ensuring that kernel memory is not mapped while running in user mode.

## 4. Conclusions

In this write-up, I didn’t just want to show two vulnerabilities. I wanted to show something deeper.

To me, Spectre is not just a vulnerability. It is a design failure. A point where CPU optimization went too far, where the chase of performance started to outperform the guarantees of security.

As we have seen, some aspects of these attacks can be mitigated. Spectre variant 2 and Meltdown can be fixed with microcode updates and architectural changes. But the core idea behind Spectre, speculative execution itself, cannot be simply “patched out.” It is fundamental to how modern processors achieve performance.

That is what makes Spectre different.

It is not a bug in a specific implementation. It is a consequence of design decisions made over decades. A trade-off that was always there, but only became visible once someone looked closely enough.

In that sense, Spectre is not just a vulnerability, it is a boundary. The point where performance optimizations break security guarantees.

And once you cross that boundary, there is no easy way back.

#### Original idea

My original idea, after reading about Spectre, was to use it as an obfuscation technique. 
Since speculative execution is invisible at the software level, I wanted to create something like a superposition state (as in quantum physics) of execution, a architectural state that simply cannot be determined or captured from software.
After a few experiments, though, it became clear the idea wouldn't work out. So I decided on writing about the vulnerabilities themselves instead.

About experiments, e.g. if you place a hardware breakpoint within the speculatively executed code, the CPU treats it no differently from normal execution and fires the breakpoint handler as usual. 
That alone was enough to kill my promising idea, though a couple of other circumstances contributed to it falling apart as well.


---

**End**

And as always, thank you for reading; I hope you learned something new.

### Credits

This write-up would not have been possible without the research and explanations provided by the following awesome authors and sources. Their work made it significantly easier for me to understand and present these concepts clearly.

- [CPUs and pipelines, how do they work? - Anton Zotin](https://scalibq.wordpress.com/2012/02/19/cpus-and-pipelines-how-do-they-work/)

- [Data Hazards and its Handling Methods - GeeksForGeeks](https://www.geeksforgeeks.org/computer-organization-architecture/data-hazards-and-its-handling-methods/)

- [Meltdown and Spectre, explained - Matt Klein](https://medium.com/@mattklein123/meltdown-spectre-explained-6bc8634cc0c2)

- [Exploring the process of virtual memory address translation - De-Engineer](https://de-engineer.github.io/Virtual-Address-Translation-and-structure-of-PTE/)