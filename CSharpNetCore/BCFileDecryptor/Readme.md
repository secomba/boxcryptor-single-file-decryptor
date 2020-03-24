# Instructions for C#

BCFileDecryptor requires the following to work:
* .Net Core 3.1
* Microsoft.AspNetCore.Cryptography.KeyDerivation (NuGet Package)

To build simply open BCFileDecryptor.sln with MS Visual Studio and run the "build solution" command in Debug mode. 

After successfully building the app navigate to /bin/Debug/netcoreapp3.1/ in any Windows terminal and run the following command to test it:

`BCFileDecryptor.exe <your parameters>`