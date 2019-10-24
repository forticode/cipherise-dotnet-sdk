### <a name="NewService"></a>Creating new services
The first step to integrating your Service Provider with Cipherise is to register a service. 
A service can be registered using [ICipheriseServiceProvider.Register()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Register_System_String_Cipherise_ICipheriseError_):

[!code[NEW_SERVICE](newservice.cs)]

> [!NOTE]
> It is the Service Providers responsibility to persist the service ID. To reuse the same service pass its service ID to
> [CreateServiceProvider()](../api/Cipherise.CipheriseSP.html#Cipherise_CipheriseSP_CreateServiceProvider_System_String_System_String_System_String_System_Int32_).