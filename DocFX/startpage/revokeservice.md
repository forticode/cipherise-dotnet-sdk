### <a name="RevokeService"></a>Revoking services
A Service Provider can revoke any services it owns by calling
[ICipheriseServiceProvider.Revoke()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Revoke_Cipherise_ICipheriseError_).
This may be done when, for example, a Cipherise integration is uninstalled.

[!code[REVOKE_SERVICE_CODE](revokeservice.cs)]

> [!WARNING]
> Revoking a service will disable it and as such deny future enrolments and authentications.