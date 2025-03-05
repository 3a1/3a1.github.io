---
title: "Analysying Insomnia - Bootkit that infects kernel with backdoor"
draft: false
date: 2025-03-03T09:16:45.000Z
description: "Analysying first bootkit that abuses SSDT hooking to infects kernel with backdoor"
tags:
  - uefi
---

### Introduction

As im sick for about 5 days so i decided to make something interesting - a Boot Service Bootkit. As a challange a also
promise myself that bootkit itself will have zero assembly, and i did it. In a result it was tiny, but in other hand quite
complex but i think i will describe all the sketchy points of how it works here. 

### Bootkit Analysis

Here, we can see a visual graph of how the infection will works at a basic level,
would be helpful to understand whats going on next.

{{< img src="22.png">}}

#### UefiMain

{{< img src="1.png">}}

**UefiMain** is simple, only thing it perfoms is it placing a hook on `ExitBootServices`.

#### ExitBootServicesHook

{{< img src="2.png">}}

**ExitBootServicesHook** starting with getting winload.efi base using **__get_rax()** from rax register (return address).
Next it gets using pattern scan a function called **BlpArchSwitchContext**, and
 makes pattern scan for the reference on **OslLoaderBlock** from which will be extracted its absolute address.

{{< img src="3.png">}}

**BlpArchSwitchContext** is made for making a switch between Firmware(Physical Memory) and Application(Virtual Memory) execution contexts.
It internaly switches the descriptor table context, but we dont care on that.

Why we need this function? We are now in **ExitBootServices**, last stage before the OS will pass its execution to the OS Kernel.
We cant hook any function that will be after the **ExitBootServices** because we have a Boot Service Driver that will be unloaded
 from system after **ExitBootServices** will be finished. So here is the point of using it, to access virtual memory we need to switch 
 out context to the Application. 
 
I think we can even not switch the context and translate the addresses from virtual to physical using for example 
**MmArchTranslateVirtualAddress** and then access it but it seems to be useless.

{{< img src="4.png">}}

**OslLoaderBlock** is a structure that holds information about system during boot but specially a system boot drivers. 
These drivers need to start before the others as they are major drivers for system. 
Without them the system itself cant launch. Such as ntfs.sys, disk.sys, acpi.sys, tpm.sys etc. The ntoskrnl also there.

They are already loaded in the memory but not started yet. We need this structure to get the os kernel virtual address.

{{< img src="5.png">}}

Here we are switching out context to Application so now we can access virtual addresses and gets the os kernel base.

##### Infecting OS Kernel

I have wonder what way of infecting i should choose for this project.
At the start i was thinking about just overwrite the code of some function in the .text section, but its the common method.
I mean the problem is not really in that because it is popular, but it is an obvius detection. 
Just need to compare the hashes of the .text section from the file on disk with the image in runtime.

So i have decided to show the other way, we will abuse the **padding** of the functions.

##### Abusing the Sections Padding

{{< img src="6.png">}}

As u can see here, we have an end of a **.text** section that was on the `.text:000000018016E600`.
But line above we will see that it magicaly jumps to the address `PAGER32C:000000018016F000` of the next section.
Its called a padding, the sections and a image itself, need to be page aligned, that means it should be dividing by **0x1000**.

{{< img src="7.png">}}

If we will check in hex-editor tab, we will see that after the end of a **.text** section there is a undefined memory.
It is a padding memory that is not initialized.
We need only something like 40 bytes for our future payload, so in our case this small bunch of memory is even too much for us.
So it will be ideal to infect kernel here with our payload.

Yes some nerd can say that os kernel doesnt have a **RWX** regions. We need for our payload to be executed an Execution permission but also
to be undetected from comparing with disk a Write permission, so this section can be overwrited in runtime and there will be no sense in
comparing that section with disk. 

U will be right, but, the thing is that some drivers change their sections with only **Read** permissions itself, even ntoskrnl did it.
The **INIT** section that have only **R-E** permissions is overwrited with some dummy data after kernel initialization.
I dont know what is for or what cause that, but i have noticed it some time ago. So u can even just overwrite this full section
and this will be not suspicius. In in the one sentence, comparing with disk all **R-E** sections is lead to false positives.

Remember that u can always find a driver with **RWX** section, set it startup as **Boot Start** and can u can overwrite its **RWX** section
without any issues. Remember that we can even change other drivers **->Charecteristic** field in runtime to make the section any permission
 we want, or maybe overwrite file on disk itself after the driver is loaded in memory :D
 Thats all just the reflection for those that will want to make a something better.

{{< img src="7.png">}}

But the questions is, what the payload we want infects kernel with?
I saw some time a cool **ekknod** project that makes possible to execute kernel functions
from usermode. I will drop a link on the end to his project. He used some shellcode with which he is overwriting the
**GetVariable** function, as i have promised myself that we will not use any asm in bootkit, we need to do it without asm.
The basic kernel mode execution payload is looks like this:

{{< img src="8.png">}}

If we will get to this function from usermode, we can execute any functions from kernel that we want.
Im not sure but i think that we can even use just **JMP** instruction in asm to the address of function
and it will also work. With **JMP** approach our payload will be just like **4 bytes** in size? Pretty tiny backdoor tho.
But as i cant use the asm here we will leave it as it is.

So the next thing if we know our payload, know where we will copy it, how we will get our usermode to execute it?
We can overwrite some Nt function with jmp to it, but as I describe above we are not interested in overwriting **.text** section.
And i have decided to make some other interesting thing, its an **SSDT Hooking**.

#### SSDT Hooking

{{< img src="9.png">}}

As we can see here. I will be not very deep into how **System Service Dispatch Table** works but I will get u to the point.
When u making a call for example **NtWriteFile** from **ntdll.dll**, in ntdll it makes a **syscall** with specific **id** of a function
 to - switch the execution to the kernel and to execute the kernel function that u have specify before.
 All the kernel functions that can be executed from usermode have own syscall id. How does a syscall know the address of each kernel function? Here is SSDT comes in game.
 **SSDT** is a table located in the **ntoskrnl** called **KeServiceDescriptorTable**, it is not exported in x64 modern systems so we are need to 
 find it somehow ourself. 
 
{{< img src="12.png">}}
 
**KeServiceDescriptorTable** is looks like this, it has four fields inside, but we are interested only in pointer to the **ServiceTable** as its the 
table with addresses to the kernel routines.
 
But the thing is, as we are dealing with it before the os kernel is even executed, **KeServiceDescriptorTable** is zero, it is **not initialized**.
But as we saw before, the **KiServiceTable** is a **pointer**, so ServiceTable is holded in some other variable in the kernel outside **KeServiceDescriptorTable**.

{{< img src="10.png">}}

As we can see, **SSDT** table is only getting initialized in the **KiInitSystem** phrase. 

{{< img src="11.png">}}

In its initialization it copying a pointer from variable called **KiServiceTable**.
Thats what we are looking for.
 
{{< img src="13.png">}}

And here we can see that it is! All kernel routines relative addresses.
But its not the end, because the **KiServiceTable** is also not initialized yet :D

To get an absolute kernel address from **ServiceTable** when the kernel is initialized we need to do something like this:

$$ RoutineAbsoluteAddress = KiServiceTableAddress + (routineOffset > > > 4) $$ 

So, somewhere in the kernel, it needs to be **compacted** or **compressed**.

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

Basicaly, to make a hook, we are need to rewrite the relative offset to our payload, thats it.
Also, need to specify that **Kernel Patch Guard** will also not catch us as we are hooking SSDT even before
it is gets initialized, so we are cool and badass.

Someone can say that the **SSDT hooking** is detected since windows 7 and any antivirus will go crazy with it.
But thats not really the truth. If we will perfom an **SSDT hook** to the other driver this will be detected, yes.
But we are perfoming a hook **inside** the same module(ntoskrnl). You can say that to detect it, some antivirus can calculate every 
absolute address in runtime and comparing it. But comparing it with what? With the addresses in the **EAT**? 
But here, in **syscalls**, there are some functions that doesnt have an **EAT export**, so then what? The only true answer is will be
calculating the absolute address from the file on disk, then calculate the absolute offsets from the runtime, but like i said
it quite complex, need to make two different calculations, but yes it will detect our hook.
 Anyway i dont think that except maybe some **EDR's**, other antiviruses or anticheats doing that.
 
We can also not even infecting the kernel with something, we can just make for example that **NtUnloadKey2** syscall will execute
 **MmCopyVirtualMemory**, by just changing the relative offset that will point to the other function. 

So, now we need to specify what exactly syscall we will perfom to hook.
I decided to use **NtShutdownSystem**, why? Because its will be likely not called often during runtime :D 
And it is exported in **EAT**, so we dont need to search by pattern for it.

{{< img src="15.png">}}

Here we are getting the **PAGE** section **address** and **size**. With it we will make **padding abusing**.
Then we are getting **NtShutdownSystem export**, we need it to saving the original function functionality.
Without it we even cant turn off our pc :D

But, as we are next copying our payload to the padding, we are not copying our **.data** section so we will have no access to **global variables**.
We need somehow to save our original **NtShutdownSystem address**.

I decided to just copy it to the memory before the function with the signature **0xDEAD** to indentify the end.
We will see later in payload how its will be extracted.
Yes, as we are inside the ntoskrnl we can just walk to its image base and gets function address from EAT, but it will impact our perfomance.

Next like i said we are copying our payload byte by byte to the padding, we are looking for function end, by **0xCC**(INT 3), that is the indicator
 of the function padding/end in binary.
 
{{< img src="16.png">}}

Here we are trying to resolve the **KiServiceTable**. 
U can say that we can just use pattern scan for reference and thats all, but the problem is that even on other 
W10 22h2 builds the pattern is different, so we will manually walk to it from kernel entry point. Fortunately its close abt.

The manual walk looks like this:

$$ KiSystemStartup->KiInitializeKernel->KiServiceTable $$

Then when we have the **KiServiceTable**, to not making syscall id hardcoded we can walk the table searching for the NtShutdownSystem
relative offset, as we have function address from **EAT** we can find its **entry** there.
Then just change the relative offset in the entry to point to the our payload.

{{< img src="17.png">}}

The end of the **ExitBootServices** is simple, we are just switching our context back to the **firmware**, then we are **restoring** our hook
and returning the original **ExitBootServices** function. After the original **ExitBootServices** function will finish its execution,
out driver will be automatically **unloaded** from memory :^(

#### Payload

{{< img src="18.png">}}

Will back to our **payload**, first we are going back in memory to get our saved **NtShutdownSystem** address.
After we will hit our **0xDEAD** signature, we know that we are in the right place and **extracting** the address.

And backthen in the project from **ekknod**, he used very cool method of hiding the arguments
 by overwriting **EntryPoint** and **ImageSize** of the current image.
So basically the calls to his hooked **GetVariable** function will looks totally legit. 
Yes, we can even use some reserved entry in local structures that is not used to store our data there.
I have start thinking about can we somehow hide the arguments on the stack? 


##### Shadow Space

{{< alert error "" >}}
Im not sure
{{< /alert >}}

{{< img src="19.png">}}

As u can see here, the default **__fastcall** calling convention that is used in windows on x64 passing the **first four** arguments in the registers
then the other one via stack. But it is also presaving the memory space called **shadow space** for these registers. 
So if the first four registers are not zero, meaning that shadow space is not used for presaving it and the shadow space is skipped.
Thats it the way that i have thinking when coding it, but at the time of writing this im not sure.
Google not really showing anything useful about how its going in syscalls, the only thing i know that it is passed in the 
**KiSystemCall64** and if **KVA** enabled it goes to the **KiSystemCall64Shadow**. Then it makes a kernel stack and pass the registers to the memory.
I have found that its gets arguments after pushing rax from stack and place them into registers. 
Anyway, as we are not passing the argument by the default registers but storing it in the usermode stack i think it will be anyway
confusing for any systems that will try to monitor our call.

Syscall saves the usermode **RSP** in the **GS** cpu segment register.
In kernel GS segment holds **_KPCR** structure.

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

As we can see in the **UserRsp** we can get the usermode stack address.
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

Here is basic implementation in usermode, it has comments so i have nothing to describe here. 
Will see how it is gets extracted in kernel mode.

{{< img src="20.png">}}

We are reading **GS** segment register of the CPU with offset that 
point to the **->UserRsp** then we are getting the **magic** offset. 
Remember that we are calling a call in usermode, call pushes **8 bytes** for storing RAX on stack so we need to add
it also.
Then we are getting our **hidden argument** from **RSP** that is an pointer to the structure and in the end we are executing our payload.

Overall, is it really something useful? I think no. But I found it interesting.
Anyway i think if someone will look deep into that can find better way to do it.
In the thread context we have some debug,exceptions fields, for example LastExceptionFromRip, we can simply overwrite it with our argument.
And then in kernel mode gets this field in **_KPCR->_KPRCB->_KPROCESSOR_STATE->_CONTEXT**.

{{< img src="21.png">}}

At the end in getting anything together we are getting this one tiny usage example of our backdoor with kernel functions execution.

Thank you for reading; I hope you learned something new!

The full bootkit code with usermode can be found on [GitHub](https://github.com/3a1/Insomnia).
