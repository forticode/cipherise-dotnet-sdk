### <a name="PushAuth"></a>Push authentication
Push authentication is a Cipherise authentication that is sent to a particular user's device. This 
can only be used when the Service wants to target a specific user and the username and deviceid are
known for that user. Ideally, this is suited for workflow related cases, such as authorising a 
banking transaction (targeted user is the owner of the transferring account), or seeking permission
for a privileged activity (targeted user is the supervisor of the user seeking permission).

The following steps need to occur in a Push Authentication:

1. The Service Provider looks up the username (the name the user was enrolled to Cipherise as) of the authenticating user.

2. The Service Provider calls 
[ICipheriseServiceProvider.RetrieveUsersDevices](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_RetrieveUsersDevices_Cipherise_ICipheriseDevice_)
to determine the users device ID to send the authentication.
Note that there can be more than one device registered to a user. In this situation, the Service Provider will need to determine which one(s) to 
send the authentication to.

3. The Service Provider calls 
[ICipheriseServiceProvider.Authenticate()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Authenticate_Cipherise_ICipheriseAuthenticate_), 
passing in an instance to [ICipheriseAuthenticatePush](../api/Cipherise.ICipheriseAuthenticatePush.html).

4. Methods of 
[ICipheriseAuthenticate](../api/Cipherise.ICipheriseAuthenticate.html)
are called by the SDK to determine the type of authentication required by the Service Provider.

5. The user responds to the authentication notification on their device and solves the 
authentication challenge.

6. When the authentication has completed the SDK calls
[ICipheriseAuthenticate.Authenticated()](../api/Cipherise.ICipheriseAuthenticate.html#Cipherise_ICipheriseAuthenticate_Authenticated_Cipherise_CipheriseAuthenticationResponse_System_String_System_String_System_String_)
to instruct the Service Provider of the authentication result.

[!code[PUSH_AUTH_CODE](pushauth.cs)]