### <a name="NewService"></a>Creating new services
The first step to integrating your Service Provider with Cipherise is to register a service. 
A service can be registered using [ICipheriseServiceProvider.Register()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Register_System_String_Cipherise_ICipheriseError_):

[!code[NEW_SERVICE](newservice.cs)]

> [!Note]
>It is the Service Providers responsibility to persist the service ID as the only
>way to reuse the same service is to pass the service ID to 
>[CreateServiceProvider()](../api/Cipherise.CipheriseSP.html#Cipherise_CipheriseSP_CreateServiceProvider_System_String_System_String_System_String_System_Int32_).