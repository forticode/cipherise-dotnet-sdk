### <a name="RevokeUser"></a>Revoking users from a service
A Service Provider can revoke a user by calling
[ICipheriseServiceProvider.RevokeUser()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_RevokeUser_Cipherise_ICipheriseRevokeUser_).
This could be called for a number of reasons. For example, a user leaves an organisation and is no 
longer authorised for access. To regain access, the user must re-enrol.

[!code[REVOKE_USER_CODE](revokeuser.cs)]

> [!WARNING]
> Revoking a user will deny any future authentications to the service. The user must re-enrol to the service to allow authentications.