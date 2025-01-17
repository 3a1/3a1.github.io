---  
title: "Анализ Calypso — UEFI Bootkit для Windows"  
draft: false  
date: 2024-12-31T10:13:20.000Z  
description: "Анализ моего UEFI Bootkit с взаимодействием через usermode"  
tags:  
  - uefi  
---  

### Введение  

На прошлой неделе я решил создать простой UEFI Bootkit для Windows с взаимодействием через usermode.  
Я не нашел похожих проектов на GitHub, поэтому решил сделать его сам(именно с нормальной коммуникацией через usermode).  

### Анализ Bootkit  

{{< img src="0.png">}}  

Здесь мы видим графическое представление работы Bootkit на базовом уровне.  
Это поможет лучше понять, что будет происходить дальше.  

#### UefiMain  

{{< img src="1.png">}}  

В `UefiMain` буткит выполняет две основные задачи:  
Во-первых, сохраняет оригинальный адрес функции `ExitBootServices`, чтобы восстановить его позже, и устанавливает хук на `ExitBootServices`, перенаправляя вызовы в `ExitBootServicesWrapper`.  
Во-вторых, создает событие `SetVirtualAddressMap`, которое будет объяснено позже.  

#### ExitBootServices Wrapper (asm)  

{{< img src="2.png">}}  

В `ExitBootServicesWrapper` цель — извлечь адрес возврата из регистра `RSP`.  
Как только адрес возврата получен, выполнение передается функции `ExitBootServicesHook`.  
Именно поэтому мы не можем использовать событие `ExitBootServices` — внутри события невозможно получить адрес возврата.  

#### ExitBootServices Hook

{{< img src="3.png">}}  

В `ExitBootServicesHook` задача заключается в нахождении базового адреса `winload.efi`.  
Поскольку `ExitBootServices` вызывается из `winload.efi`, и у нас есть его адрес возврата, мы знаем, что он указывает на область внутри `winload.efi`.  
Исполняемые образы всегда загружаются с начала страницы памяти, поэтому базовый адрес всегда будет делиться на 0x1000.  
Кроме того, все исполняемые образы имеют заголовок DOS в начале, начинающийся с определенного magic значения.  
Имея эту информацию, мы можем идти назад по памяти, страница за страницей, считывая первые байты каждой страницы и проверяя значение DOS magic для определения базового адреса.  

{{< img src="4.png">}}  

Следующим шагом является определение адреса `OslArchTransferToKernel`.  
Почему именно `OslArchTransferToKernel`? Эта функция вызывается, когда `winload.efi` завершает работу, и передает адрес `LoaderBlock`.  
В структуре `LoaderBlock` содержится список `LoadOrderListHead`, в котором находится адрес `ntoskrnl.exe`.  
Для этого мы используем простой сканер по паттерну, чтобы найти адрес `OslArchTransferToKernel`, и устанавливаем на него хук.  

#### SetVirtualAddressMap Event

{{< img src="5.png">}}  

Помните событие, созданное в `UefiMain`? Сейчас настало его время.  
Цель этого события — преобразовать адрес нашего хука из физического в виртуальный.  
До этого момента система работает только с физической памятью без виртуального адресного пространства.  
На следующем этапе я объясню детали.  

#### OslArchTransferToKernel Hook

{{< img src="6.png">}}  

На этом этапе у нас есть адрес `LoaderBlock`, и мы обходим структуру `LIST_ENTRY`, чтобы найти базовый адрес `ntoskrnl.exe`.  
Получив базовый адрес `ntoskrnl.exe`, следующий шаг — выбрать функцию в ядре для установки хука.  

Я выбрал функцию `NtUnloadKey` по нескольким причинам.  

{{< img src="7.png" caption="Подсказка — часто функции, являющиеся syscall'ами ядра, начинаются с префикса Nt или Zw">}}  

Во-первых, мы хотим установить связь между пользовательским режимом и драйвером UEFI.  
Для этого наша функция ядра должна вызываться как syscall из библиотеки пользовательского режима `ntdll.dll`.  

{{< img src="8.png">}}  

Основная причина выбора именно `NtUnloadKey` в том, что она является враппером для функции `CmUnloadKey`.  
Что это значит?  
Как вы, возможно, знаете, у Windows есть функция безопасности, называемая `Kernel Patch Guard` (KPP).  
Ее задача — сканировать память ядра на наличие изменений и вызывать BSOD, если они обнаружены.  
Мы обходим KPP, модифицируя ядро до его выполнения, чтобы Patch Guard сравнивал уже измененное ядро с тем, что в памяти.  
Однако проблема возникает при использовании хука с "трамплином".  
Когда хук установлен, функция сначала прыгает на хук, выполняет свою работу, восстанавливает измененные байты, вызывает оригинальную функцию, а затем снова применяет "трамплин".  
С активным KPP мы не можем удалять хук, так как это приведет к изменению ядра во время выполнения и вызовет синий экран от KPP.  
Поэтому нам нужно найти способ заменить функционал оригинальной функции, не вызывая ее напрямую.  
Функция-впаппер, такая как `NtUnloadKey`, идеально подходит для этого, так как чтобы восстановить оригинальный функционал нам надо просто передать параметры в другую функцию ядра.

#### NtUnloadKey Hook

{{< img src="9.png">}}  

В этой функции мы проверяем, соответствует ли переданный параметр нашей структуре команды. 
Если нет, мы возвращаем выполнение в `CmUnloadKey`, имитируя поведение оригинальной функции. 
Если это наша команда, выполнение передается в `dispatcher` (обработчик комманд).  

### Анализ пользовательского режима  

{{< img src="10.png">}}  

Как мы помним, функция `NtUnloadKey` из `ntdll.dll` является syscall'ом в `NtUnloadKey` находящимся в `ntoskrnl.exe`.  
Таким образом, usermode может взаимодействовать с нашим хуком `NtUnloadKey`, вызывая эту функцию через `ntdll.dll`.  
Юзермод простой, но выполняет свою задачу.  

Спасибо за внимание! Надеюсь, вы узнали что-то новое.  

Исходный код Bootkit доступен на [GitHub](https://github.com/3a1/Calypso).  