---
title: "Analysying Insomnia - Bootkit that infects kernel with backdoor"
draft: false
date: 2025-03-03T09:16:45.000Z
description: "Analysying first bootkit that abuses SSDT hooking to infects kernel with backdoor"
tags:
  - uefi
---

### Introduction

As I was sick for about 5 days so I decided to make something interesting - a boot service bootkit. As a fun challange, I also
promised myself that bootkit will have zero assembly, and I successfully did it. The result? it was tiny, quite
complex. This blog post we'll be discussing how it works. Lets dive deep into it. 

### Bootkit Analysis

Here, we can see a visual graph of how the infection will works at a basic level,
it would be really helpful to understand whats going on next.

{{< img src="22.png">}}

#### UefiMain

{{< img src="1.png">}}

**UefiMain** is simple, only thing it performs is placing a hook on `ExitBootServices`.

#### ExitBootServicesHook

{{< img src="2.png">}}

**ExitBootServicesHook** starts by getting `winload.efi` base using **__get_rax()** from rax register (return address).
Next it pattern-scans a function called **BlpArchSwitchContext** locate the context‑switch routine and
 also it tries to pattern scan for the reference of **OslLoaderBlock** to extract its absolute address.

{{< img src="3.png">}}

The task of **BlpArchSwitchContext** is to switch between Firmware (Physical Memory) and Application (Virtual Memory) execution contexts.
It internaly switches the descriptor table context but we dont care about that.

Why do we need this function? We are now in **ExitBootServices** which is the last stage before the OS will pass its execution to the OS kernel.
We can't hook any function that will be after the **ExitBootServices** because we have a Boot Service Driver that will be unloaded
 from system after **ExitBootServices** finishes its execution. So the actual point of using it is to access virtual memory, we need to switch 
 out context to the Application. 
 
 I think we can just translate the addresses from virtual to physical using **MmArchTranslateVirtualAddress** (for example) and then access them without the context switch but it seems to be useless.

{{< img src="4.png">}}

**OslLoaderBlock** is a structure that holds information about system and system boot drivers during boot. 
These drivers need to start before the others as they are major important drivers for system. 
Without them, the system itself can't launch. Some examples of such drivers are `ntfs.sys`, `disk.sys`, `acpi.sys`, `tpm.sys` etc. The ntoskrnl also there.

By the way, they are already loaded in the memory but not started yet. We need this structure to get the OS kernel's virtual address.

{{< img src="5.png">}}

Here we are switching out context to Application so we can access the virtual addresses and gets the OS kernel's base.

##### Infecting OS Kernel

I have wonder what way of infecting i should choose for this project.
I was confused about what way of infection should I choose for this project.
Initially, I was thinking about just overwriting the code of some function in the **.text** section but it's a really common method.
When a method is popular enough, it gets obviously detected by AV/EDRs. This is not what we want.
So this method is detected fairly easily by AV/EDRs by just comparing the hashes of the **.text** section from the file on disk with the image in runtime (i.e. hashing on‑disk and in‑memory sections).

Finally, I landed on abusing the **padding** of the functions.

##### Abusing the Padding of Sections

{{< img src="6.png">}}

As you can see here, we have the end of a **.text** section that was on `.text:000000018016E600`.
If you observe the line above, we see that it magically jumps to the address `PAGER32C:000000018016F000` of the next section.
The gap between these is calleduninitialized padding, 
It's called a **padding**. The sections and image itself need to be page aligned, that means it should be dividing by **0x1000**.
We can abuse that uninitialized padding which is easily large enough (hundreds of bytes) to hold our payload.

{{< img src="7.png">}}

If we check that in hex-editor, we see that after the end of the **.text** section, there is a undefined memory.
It's basically the padding memory that is not initialized.
We need only something like 40 bytes for our future payload, so in our case this small chunk of memory is pretty large for us.
So it will be ideal to infect kernel here with our payload.

Well some nerd will probably say that OS kernel doesn't have **RWX** regions. We need it for our payload to be executed (Execution permission is required for this) but also to be undetected from comparing with disk (Write permission is required for this), so this section can be overwritten in runtime and it would be non-sensical comparing that section with disk. 

You will be right but the thing is that some drivers change their sections with just the **Read** permissions itself, even ntoskrnl does it.
The **INIT** section that only have the **R-E** permissions is overwritten with some dummy data after kernel initialization.
I'm not sure why it happens but I noticed it a while ago. So you can even just overwrite this entire section
and this will be not suspicious. TL;dr: comparing with disk, all **R-E** sections can lead to false positives.

Remember that you can always find a driver with **RWX** section, set it startup as **Boot Start** and can you also overwrite its **RWX** section
without any issues. Also worth noting that we can even change other driver's **->Charecteristic** field in runtime to make the section any permission
 we want, or maybe overwrite file on disk itself after the driver is loaded in memory :D
 That's all just a reflection for those who want to make something better.

{{< img src="7.png">}}

We talked about how we will infect the kernel, but the main question is what will we infect the kernel with?
Just recently, I saw a project made by **ekknod** which is called **SubGetVariable** that makes it possible to execute ANY kernel functions
from usermode. I have linked the project at the end of this post, check it out! The author used some shellcode with which they're overwriting the
**GetVariable** function. I remember that I promised myself to not use any assembly in the bootkit, I'll also need to figure out a way in which we need to do that without any assembly.
The basic kernel mode execution payload is looks like this:

{{< img src="8.png">}}

If we get to this function from usermode, we can execute any desired functions from kernel.
I'm not sure but I think that we can even use the **JMP** instruction in assembly with the address of function
and it will also work. With **JMP** approach, our payload will be just like **4 bytes** in size? Pretty tiny backdoor though.
But as I can't use assembly here, we will have to leave it as it is.

So the next thing if we know our payload, its destination, and how we will get the usermode to execute it?
We can overwrite some NT function with jmp instruction to it but as I clearly described above that we are not interested in overwriting **.text** section.
And I have decided to make some other interesting thing and it's **SSDT Hooking**.

#### SSDT Hooking

{{< img src="9.png">}}

Just so you know, I will not go into depth on how **System Service Dispatch Table** works but I will get you to the point.
When you make a call for example to **NtWriteFile** from **ntdll.dll**. In ntdll, it makes a **syscall** with specific **id** of a function
 to - switch the execution to the kernel and to execute the kernel function that you have specify before.
 All the kernel functions that can be executed from usermode have their own syscall id. How does a syscall know the address of each kernel function? Now SSDT comes in game.
 **SSDT** is a table located in the **ntoskrnl** called **KeServiceDescriptorTable**, it is not exported in x64 modern systems so we need to 
 find it somehow ourself. 
 
{{< img src="12.png">}}
 
**KeServiceDescriptorTable** looks like this, it has four fields inside but we are interested in pointer to the **ServiceTable** as its the 
table with addresses to the kernel routines.
 
But the thing is as we are dealing with it before the OS kernel is even executed, **KeServiceDescriptorTable** is zero i.e. it is **not initialized**.
But as we saw before, the **KiServiceTable** is a **pointer**, so ServiceTable is held in some other variable in the kernel outside **KeServiceDescriptorTable**.

{{< img src="10.png">}}

As we can see, **SSDT** table is only getting initialized in the **KiInitSystem** phrase. 

{{< img src="11.png">}}

In its initialization, it is copying a pointer from variable called **KiServiceTable**.
That's what we are looking for. :D
 
{{< img src="13.png">}}

We can clearly see that it contains the relative addresses of all the kernel routines (YESS :D)
But it's not the end because the **KiServiceTable** is also not initialized yet :>

To get an absolute kernel address from **ServiceTable** when the kernel is initialized, we need to do something like this:

$$ RoutineAbsoluteAddress = KiServiceTableAddress + (routineOffset > > > 4) $$ 

So somewhere in the kernel, it needs to be **compacted** or **compressed**.

{{< img src="14.png">}}

As we can see, on the second reference for **KiServiceTable** is in **KiKernelInitialization** and our table is passed to the 
**KeCompactServiceTable** function call.

```c
pCurrentEntry = pKiServiceTable;
if ( numEntries )
{
  numEntriesRemaining = numEntries;
  do
  {
    *pCurrentEntry = ((imageBase + *pCurrentEntry - (unsigned int)pKiServiceTable ) << 4) | (*pNumArguments >> 2);
    *pNumArguments++;
    pCurrentEntry++;
    numEntriesRemaining--;
  }
  while ( numEntriesRemaining );
}
```
 
**KeCompactServiceTable** basically looks like this, its work is to rebuild the relative addresses stored in the **KiServiceTable**
and compact them. 

As we are before the kernel initialization, **KiServiceTable** is storing **raw relative addresses** to the functions from the ntoskrnl base.

Basically to make a hook, we need to rewrite the relative offset to our payload, thats it.
Also **Kernel Patch Guard** will also not catch us as we are hooking SSDT even before
it is gets initialized, so we are cool here.

Some nerd now will say that the **SSDT hooking** is detected since windows 7 and any AV/EDR will go crazy with it.
But that's not really the truth. If we will perfom an **SSDT hook** to the other driver, this will be detected and flagged.
But we are perfoming a hook **inside** the same module (which is the ntoskrnl). To detect it, AV/EDRs need to calculate every 
absolute address in runtime and comparing it. But comparing it with what? With the addresses in the **EAT**? 
But here in **syscalls**, there are some functions that don't have an **EAT export** so then what? The only true answer is will be
calculating the absolute address from the file on disk and then calculate the absolute offsets from the runtime but like I said
it is quite complex, the AV/EDR needs to make two different calculations but that WILL DETECT OUR HOOK.
 Anyways I don't really think that any AV/EDR is doing that except a few (we really need someone to test this, don't we huh? ).
 
We can't infect the kernel with anything, we can just make for example the **NtUnloadKey2** syscall to execute
 **MmCopyVirtualMemory** by just changing the relative offset that will point to the other function. 

So now we need to specify which syscall will perfom to hook.
I decided to use **NtShutdownSystem**, why? Because it is likely that it will not be called often during runtime :D 
And it is exported in **EAT**, so we don't need to search by pattern for it.

{{< img src="15.png">}}

Here we are retrieving the **PAGE** section **address** and **size**. With it we will make **padding abuse**.
Then we will fetch **NtShutdownSystem export**, we need it to save the original function functionality.
Without it, we even can't turn off our pc Lol :D

As we are copying our payload to the padding, we are not copying our **.data** section so we won't be able access the **global variables**.
We need to save our original **NtShutdownSystem address**.

I decided to just copy it to the memory before the function with the signature **0xDEAD** to identify the end.
We will see later how is will be extracted, in the payload.
As we are inside the ntoskrnl, we can just walk to its image base and gets function address from EAT but it will impact our perfomance.

Next as I said, we are copying our payload byte by byte to the padding, we are looking for function end, by **0xCC**(INT 3), that is the indicator
 of the function padding/end in binary.
 
{{< img src="16.png">}}

Here we are trying to resolve the **KiServiceTable**. 
You might think that we can just use the pattern scan for reference and that's all, but the problem is that even on other
Windows 10 22H2 builds, the pattern is different, so we will have to manually walk to it from the kernel entry point. Fortunately, it's close to ABT.

The manual walk looks like this:

$$ KiSystemStartup->KiInitializeKernel->KiServiceTable $$

Then when we have the **KiServiceTable** to not make the syscall id hardcoded, we can walk the table searching for the NtShutdownSystem's
relative offset, as we have function address from **EAT**, we can find its **entry** there.
Then just change the relative offset in the entry to point to our payload.

{{< img src="17.png">}}

The end of the **ExitBootServices** is simple, we are just switching our context back to the **Firmware**, then we are **restoring** our hook
and returning the original **ExitBootServices** function. After the original **ExitBootServices** function finishes its execution,
our driver will be automatically **unloaded** from memory :^(

#### Payload

{{< img src="18.png">}}

Will back to our **payload**, first we are going back in memory to get our saved **NtShutdownSystem** address.
After that we will hit our **0xDEAD** signature, then we know that we are in the right place and **extracting** the address.

And in the project **SubGetVariable** by **ekknod**, the author used very cool method of hiding the arguments
 by overwriting **EntryPoint** and **ImageSize** of the current image.
So basically the calls to their hooked **GetVariable** function will look totally legitimate. 
We can even use some reserved entry in local structures that is not used to store our data there.
I have started thinking about hiding the arguments on the stack somehow lately. 


##### Shadow Space

{{< alert error "" >}}
I'm not sure
{{< /alert >}}

{{< img src="19.png">}}

As you can see here, the default **__fastcall** calling convention that is used in Windows on x64 passing the **first four** arguments in the registers
then the other one via stack. But it is also presaving the memory space called **shadow space** for these registers. 
So if the first four registers are not zero, meaning that shadow space is not used for presaving it and the shadow space is skipped.
That the way that I have been thinking when coding the project but at the time of writing this post, I'm not really sure.
I searched a lot via Google but its not really showing anything useful about how its going in syscalls, the only thing I know that it is passed in the 
**KiSystemCall64** and if **KVA** enabled it goes to the **KiSystemCall64Shadow**. Then it makes a kernel stack and pass the registers to the memory.
I have found that its gets arguments after pushing rax from stack and place them into registers. 
Anyways, as we are not passing the argument by the default registers instead storing it in the usermode stack, I think it will be
confusing for any system that will try to monitor our call.

Syscall saves the usermode **RSP** in the **GS** cpu segment register.
In the kernel, GS segment holds **_KPCR** structure.

```c
struct _KPCR
{
    union
    {
        struct _NT_TIB NtTib;                                               //0x0
        struct
        {
            union _KGDTENTRY64* GdtBase;                                    //0x0
            struct _KTSS64* TssBase;                                        //0x8
            ULONGLONG UserRsp;                                              //0x10
}; 
```

As we can see in the **UserRsp**, we can get the usermode stack address.
Also we can use the **TrapFrame** to get from there **RSP** and any other register that is passed from usermode.

##### Usermode

```asm
    ; allocate shadow space
    sub rsp, 32

    ; place signature
    mov WORD PTR [rsp + 30], 0DEADh

    ; store arg in shadow space
    mov QWORD PTR [rsp + 22], rcx

    ; moving first arg
    mov rcx, 1

    ; call
    call QWORD PTR NtShutdownSystem

    ; Restore stack
    add rsp, 32

    ret
```

Here is basic implementation in usermode, pretty much self-explanatory.
We will see how it is gets extracted in kernel mode.

{{< img src="20.png">}}

We are reading **GS** segment register of the CPU with offset that 
point to the **->UserRsp** then we are getting the **magic** offset. 
Remember that we calling a call in usermode, call pushes **8 bytes** for storing RAX on stack so we need to add
it too.
Then we are getting our **hidden argument** from **RSP** that is an pointer to the structure and in the end, we are executing our payload.

Overall the question arises, is it really something useful? In my opinion, nope but I found it interesting.
Anyways I think if someone will look deep into that topic, they can find better way to do it.
In the thread context we have some debug, exceptions fields, for example LastExceptionFromRip, we can simply overwrite it with our argument.
And then in kernel mode gets this field in **_KPCR->_KPRCB->_KPROCESSOR_STATE->_CONTEXT**.

{{< img src="21.png">}}

At the end in getting anything together we are getting this one tiny usage example of our backdoor with kernel functions execution.

Thank you for reading; I hope you learned something new!

The full bootkit code with usermode can be found on [GitHub](https://github.com/3a1/Insomnia).
Checkout the **SubGetVariable** project by [ekknod](https://github.com/ekknod) on [GitHub](https://github.com/ekknod/SubGetVariable).
