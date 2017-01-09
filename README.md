```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - StackOverflow Exploit

Classic StackOverflow exploit, which exploits a vulnerable function within the HEVD Kernel driver.

# How does this exploit work:

* First allocate a RWX memory page in which we host our Shellcode.
* Copy our Token Stealing Shellcode (including the recovery opcodes) into the executable memory page.
* Get a Handle to the HacksysExtremeVulnerableDriver device.
* The memcpy (RtlCopyMemory) within the vulnerable function doesn't do any bounds checking, so we can corrupt the stackframe and control eip by overwriting the functions return address.  
* Allocate the Userbuffer and fill it with enough bytes till you get to the return address of the vulnerable function on the stack.
* Overwrite the return address with a pointer to our ShellCode page in Userland (this works in Windows 7 because it doesn't have kernel SMEP protection).
* Use the DeviceIoControl() with the IOCTL code of our device/function to send our Userbuffer to the driver in Kernelspace.
* The vulnerable function within the kernel driver overwrites the KernelBuffer and corrupts the functions stackframe.
* The Return address will be overwritten with the pointer to our Shellcode so EIP (Instruction Pointer) will jump to our Shellcode in Userland.
* Our Shellcode replaces the token handle of the exploit process with the token handle of PID 4 (System), creates a new cmd.exe process using this System Token and recovers the Stackframe.  

Runs on:

```
This exploits only works on Windows 7 x86 SP1 (Version 6.1.7601).
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
```
