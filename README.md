### Zuneslayer

A suite of exploits for the Microsoft Zune music player

----

#### Zune 30 / 120
`./ZuneSD/zuneslayer_kernel/zune30/template` is a kernel exploit targeting the latest Zune 30 firmware (v3.3) install using XNA + EDT

On first run this sets a flag making all future apps run with kernel privileges, on second run will use those privs as a demo.

Because this launches through XNA it cannot be used to decrypt Apps or DRM protected media, as those keys are wiped on launch until next reboot.

Trying to read the bootrom doesn't seem to work, likely due to some form of lockout.

---- 
#### Zune HD
`./ZuneHD/zuneslayer_kernel/template` is a kernel exploits for the latest Zune HD firmware (v4.5) install using XNA
Uses OpenZDK to gain native code execution, then uses a arbitrary write in the vulnerable kernel driver "libnmvwavedev.dll" to change the permission maps for arguments to the `GetExitCodeThread` function.
This allows passing kernel addresses as the exit code destination address, which is used to replace the `GetFSHeapInfo` syscall with an arbitrary unprivileged kernel read/write.

When launched through XNA normally the same key wipe mechanism as the Zune 30 applies.

Due to secure boot settings, either set via bootloader or bootrom, dumping the bootrom of the SOC is not possible (but you can dump the first 1k).

`./ZuneHD/browser_exploit/index.html` is an alternative userspace entrypoint via the browser's jscript engine, based on [CVE-2019-1367](https://googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2019/CVE-2019-1367.html)
This vulnerability is used to create a fake string that can be used to leak the address of any heap object by walking the GC tree to construct a fake object and vtable. This executes a ROP chain that marks some shellcode as executable and jumps to it. 

This can be used to chain the above kernel exploit's "native exe" directly, which as this never launches the xna/OpenZDK part, skips the key wipe mentioned above. This allows dumping of encrypted content such as apps.


`ZuneHD/zuneslayer_debug` is a tool for communicating with a debugger daemon that is launched by the kernel exploit to dump apps and debug binaries, without needing to re-run the exploit.
