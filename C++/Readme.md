# Build process for C++

The build process was tested with version **5.4.0 (20160609) of g++** on **Ubuntu 16.04.4** and version **4.9.2 of g++** on **Windows 10 (cygwin)**. If you have any trouble compiling please make sure you have a compatible setup to one of the above.

The subfolders `/C++/build/` and `/C++/build_win/` contain basic Makefiles which, with the default target, will compile the source code in a debug configuration using make.
The C\+\+ binary needs to be statically linked againt the **Crypto\+\+** library, which you can get from https://www.cryptopp.com/ or https://github.com/weidai11/cryptopp. Please follow the library's (debug) build instructions for your plattform and copy the resulting file (*libcryptopp.a*) into `/C++/cryptopp/lib/debug/`. The code has been tested with **version 7.0**.

After following the steps above you should be able to successfully run the Makefile like any other. You can also delete the build output with the 'clean' target of the Makefile.
