# ParallelNimcalls

This repo contains the Nim variant of the recent MDSec's research which is Parallel Syscalls.

You can use this code to load a clean version of `ntdll.dll` from the filesystem.

![image](https://user-images.githubusercontent.com/26549173/149503348-8e990e6c-6350-4636-ae0b-3c408b9d1e75.png)


# Compilation

You can directly compile the source code with the following command:

`nim c -d:release --opt:size --passC:"-masm=intel" Main.nim`

In case you get the error "cannot open file: winim/lean", you should also install winim dependency:

`nimble install winim`

# Reference

- https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/
