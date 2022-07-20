# PeView PE 结构解析器

<div align=center>
  
![image](https://user-images.githubusercontent.com/52789403/179880740-12c9fbb8-8db4-40a3-a558-32f050b8294a.png)
  
</div>

一款使用C++开发的命令行交互版WindowsPE文件解析器。
<br>

版本：3.0
<br>
发布日期：2021-07-19 13:35

<br>

**打开PE文件:** 使用`Open`一次性打开文件，只有打开后才可以对其进行其他操作，打开文件需要使用`Open`命令跟路径。
```
[Pe View] # Open --path d://Win32Project.exe
[+] 已读入文件
```

**查询PE头数据:** PE头查询命令有两个，使用`Dos`可查询DOS头部，使用`Nt`命令则可查询NT头部，目前只列出了常用字段。
```
[Pe View] # Dos
----------------------------------------------------------------------
                 十六进制        十进制
----------------------------------------------------------------------
DOS标志:         00005A4D        00023117
IP入口:          00000000        00000000
CS入口:          00000000        00000000
PE指针:          000000E8        00000232
----------------------------------------------------------------------
[Pe View] #
[Pe View] # Nt
----------------------------------------------------------------------
                 十六进制        十进制
----------------------------------------------------------------------
NT标志:         0x00004550       00017744
运行平台:       0x0000014C       00000332
入口点：        0x0001121C       00070172
镜像基址：      0x00400000       04194304
镜像大小：      0x0001F000       00126976
代码基址：      0x00001000       00004096
内存对齐：      0x00001000       00004096
文件对齐：      0x00000200       00000512
子系统：        0x00000002       00000002
区段数目：      0x00000007       00000007
时间日期标志：  0x62D76132       1658282290
首部大小：      0x00000400       00001024
特征值：        0x00000102       00000258
校验和：        0x00000000       00000000
可选头部大小：  0x000000E0       00000224
RVA 数及大小：  0x00000010       00000016
----------------------------------------------------------------------
```

**查询数据目录表:** 查询数据目录表可执行`DataDirectory`命令获取，其中包括了`RVA,FOA,Size`等基本信息。
```
[Pe View] # DataDirectory
-------------------------------------------------------------------------------------------------------
编号     目录RVA         目录FOA         Size长度(十进制)        Size长度(十六进制)      功能描述
-------------------------------------------------------------------------------------------------------
001      0x00000000      0xFFFFFFFF      00000000                0x00000000             Export symbols
002      0x0001A1E0      0x00006DE0      00000080                0x00000050             Import symbols
003      0x0001B000      0x00007800      00009612                0x0000258C             Resources
004      0x00000000      0xFFFFFFFF      00000000                0x00000000             Exception
005      0x00000000      0xFFFFFFFF      00000000                0x00000000             Security
006      0x0001E000      0x00009E00      00000972                0x000003CC             Base relocation
007      0x00016820      0x00005020      00000056                0x00000038             Debug
008      0x00000000      0xFFFFFFFF      00000000                0x00000000             Copyright string
009      0x00000000      0xFFFFFFFF      00000000                0x00000000             Globalptr
010      0x00000000      0xFFFFFFFF      00000000                0x00000000             TLS
011      0x00017560      0x00005D60      00000064                0x00000040             Loadconfiguration
012      0x00000000      0xFFFFFFFF      00000000                0x00000000             Bound Import
013      0x0001A000      0x00006C00      00000480                0x000001E0             IAT
014      0x00000000      0xFFFFFFFF      00000000                0x00000000             Delay Import
015      0x00000000      0xFFFFFFFF      00000000                0x00000000             COM descriptor
016      0x00000000      0xFFFFFFFF      00000000                0x00000000             NoUse
-------------------------------------------------------------------------------------------------------
```

**查询节表:** 查询程序中的节表可使用`Section`命令查询。
```
[Pe View] # Section
----------------------------------------------------------------------------------------------------
编号     节区名称       虚拟偏移        虚拟大小        实际偏移        实际大小        节区属性
----------------------------------------------------------------------------------------------------
1        .textbss        0x00001000      0x00010000      0x00000000      0x00000000      0xE00000A0
2        .text           0x00011000      0x00004366      0x00000400      0x00004400      0x60000020
3        .rdata          0x00016000      0x00002069      0x00004800      0x00002200      0x40000040
4        .data           0x00019000      0x00000769      0x00006A00      0x00000200      0xC0000040
5        .idata          0x0001A000      0x00000AB9      0x00006C00      0x00000C00      0x40000040
6        .rsrc           0x0001B000      0x0000258C      0x00007800      0x00002600      0x40000040
7        .reloc          0x0001E000      0x00000599      0x00009E00      0x00000600      0x42000040
----------------------------------------------------------------------------------------------------
```

**查询所有导入表:** 导入表的查询有多个命令，其中`ImportAll`用于查询所有导入过的模块以及该模块的导入函数。
```
[Pe View] # ImportAll
---------------------------------------------------------------------------------------------------
Hint值           API序号         文件RVA         VA地址          函数名称        模块: [ USER32.dll ]
---------------------------------------------------------------------------------------------------
[  547]          000107838       0000713E        0041A53E        LoadIconW
[  545]          000107824       00007130        0041A530        LoadCursorW
[  233]          000107812       00007124        0041A524        EndPaint
[   14]          000107798       00007116        0041A516        BeginPaint
[  855]          000107782       00007106        0041A506        UpdateWindow
[  829]          000107758       000070EE        0041A4EE        TranslateAcceleratorW

-----------------------------------------------------------------------------------------------------
Hint值           API序号         文件RVA         VA地址          函数名称        模块: [ KERNEL32.dll ]
-----------------------------------------------------------------------------------------------------
[  615]          000108820       00007514        0041A914        GetModuleHandleW
[  611]          000108798       000074FE        0041A8FE        GetModuleFileNameW
[  414]          000108784       000074F0        0041A8F0        FreeLibrary
[ 1443]          000108768       000074E0        0041A8E0        VirtualQuery
[  674]          000108750       000074CE        0041A8CE        GetProcessHeap
[  819]          000108738       000074C2        0041A8C2        HeapFree
```








