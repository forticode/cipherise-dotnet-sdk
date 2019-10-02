### <a name="WaveAuth"></a>Wave authentication
Wave authentication is where the user 'waves' their device over a WaveCode to trigger
the authentication process.

The following steps need to occur in a Wave Authentication:

1. The Service Provider calls 
[ICipheriseServiceProvider.Authenticate()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Authenticate_Cipherise_ICipheriseAuthenticate_), 
passing in an instance to [ICipheriseAuthenticateWave](../api/Cipherise.ICipheriseAuthenticateWave.html).

2. The SDK informs the Service Provider via
[ICipheriseAuthenticateWave::DisplayWaveCode()](../api/Cipherise.ICipheriseAuthenticateWave.html#Cipherise_ICipheriseAuthenticateWave_DisplayWaveCode_System_String_)
that an authorisation WaveCode is ready to be presented to the user.

3. The user scans the WaveCode with the Cipherise App.

4. Methods of 
[ICipheriseAuthenticate](../api/Cipherise.ICipheriseAuthenticate.html)
are called by the SDK to determine the type of authentication required by the Service Provider.

5. The user responds to the authentication notification on their device and solves the 
authentication challenge.

6. When the authentication has completed the SDK calls
[ICipheriseAuthenticate.Authenticated()](../api/Cipherise.ICipheriseAuthenticate.html#Cipherise_ICipheriseAuthenticate_Authenticated_Cipherise_CipheriseAuthenticationResponse_System_String_System_String_System_String_)
to instruct the Service Provider of the authentication result. 

[!code[WAVE_AUTH_CODE](waveauth.cs)]