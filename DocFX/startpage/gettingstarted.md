---
## Getting Started
This SDK interacts with a Cipherise Server to perform service registrations, user enrolments, and user authentications.

> [!TIP]
> A Cipherise Server can be created at [developer.cipherise.com](https://developer.cipherise.com).

In Cipherise terminology the application that is using the Cipherise SDK is a Service Provider.

The main entry point for the SDK is 
[CreateServiceProvider()](../api/Cipherise.CipheriseSP.html#Cipherise_CipheriseSP_CreateServiceProvider_System_String_System_String_System_String_System_Int32_):

```CS
using Cipherise;
...
ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider("https://your.cipherise.server.here");
```
From the [ICipheriseServiceProvider](../api/Cipherise.ICipheriseServiceProvider.html) interface all other 
Cipherise functionality can be initiated, such as service management, user enrolments, user authentications and revocations.

[!include[I_SERVE_MAN](servicemanagement.md)]
[!include[I_USER_MAN](usermanagement.md)]
[!include[I_AUTH](authentication.md)]
[!include[I_ADV](advanced.md)]