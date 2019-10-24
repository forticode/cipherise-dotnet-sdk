# **Cipherise .NET SDK** v6.3.0
## Introduction
Cipherise does away with passwords and usernames, giving your customers an easy, secure
login with their mobile device. With a simple, quick scan of a WaveCode, they can achieve 
multi-factor authentication in a single action.

 * Move towards a passwordless experience for your customers.
 * No more complicated passwords and usernames.
 * A simple, fast experience that is consistent across multiple services.
 * No more credential sharing.
 
By design Cipherise decentralises critical information (identity, credentials and critical 
data). Each user's credentials are encrypted and stored in a secure enclave on their personal
device. The credentials are never stored elsewhere or transmitted through a browser. This 
protects your customers' data and digital identity.

 * All Cipherise authentication transactions are decentralised and completed on a user's mobile phone.
 * Credentials are stored locally on the user's phone in encrypted form, not centrally with the service provider.
 * Credentials are never transmitted or stored outside of the user's phone.
## Build

The Cipherise .NET SDK is built using the Visual Studio 2017 solution file CipheriseDotNetSDK.sln which produces the following binaries:

|||
|:-:|:-|
|CipheriseSDK.dll| The Cipherise SDK.  |
|CipheriseExample.exe| The executable of the example program. |

## Dependancies

The Cipherise .NET SDK depends on the following 3rd party libraries:

|||
|:-:|:-|
|BouncyCastle.Crypto.dll| The 3rd party crypto library used by the Cipherise SDK to perform the PKI. |

## Installation

For installation instruction please visit the [Cipherise SDK Nuget](https://www.nuget.org/packages/CipheriseSDK/) page for the official builds.

## Usage

Use the following commands to create a dotnet application:

```
dotnet new console
dotnet add package CipheriseSDK
```

Next, modify Program.cs to call the Cipherise SDK API.
## Getting Started
This SDK interacts with a Cipherise Server to perform service registrations, user enrolments, and user authentications.

> **_TIP_**
> A Cipherise Server can be created at [developer.cipherise.com](https://developer.cipherise.com).

In Cipherise terminology the application that is using the Cipherise SDK is a Service Provider.

The main entry point for the SDK is 
[CreateServiceProvider()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.CipheriseSP.html#Cipherise_CipheriseSP_CreateServiceProvider_System_String_System_String_System_String_System_Int32_):

```CS
using Cipherise;
...
ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider("https://your.cipherise.server.here");
```
From the [ICipheriseServiceProvider](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html) interface all other 
Cipherise functionality can be initiated, such as service management, user enrolments, user authentications and revocations.

### Service Management

The Service Provider can query a Cipherise Server for information to determine 
the supported functionality:
 * [Querying a Cipherise server](#QueryCS)

For users to be able to enrol and authenticate to a Service Provider one or more 
services need to be created:
  * [Creating new services](#NewService)
  * [Revoking services](#RevokeService)
### User Management
In order to interact with Cipherise, a user must be enrolled to a service. This 
interaction is the key point in which the trust relationship is established. Future authentications
rely on the trust established at enrolment time. For a service that is binding a secure profile to 
their Cipherise enrolment, a secure environment must be considered. For example, adding Cipherise
to an existing profile in a site may require the user to be logged in. If Cipherise is being used
for physical access, it could require being present in the physical environment for enrolment 
binding to be accepted. Alternatively, an SMS could also be sent from a profile to the owner's 
device.

Some services need not require a personalised account, and it may be sufficient to offer the 
instantaneous creation of an anonymous account, simply by the scanning of a WaveEnrol code.
  * [Enrolling a user to a service](#EnrolUser)
  * [Revoking users from a service](#RevokeUser)
### Authentications

Once a user is enrolled to a Cipherise service, authentication is then allowed.
Cipherise Authentication is bi-directional, meaning that the Cipherise service will verify the
user's device and the user's device will verify the Cipherise service. 
Authentication can be used in a variety of ways. It can be simple access control, physical or 
digital but it can also be part of a workflow. Workflows could include financial 
transaction approval, manager approval or multiple party approval for example.

There are two types of authentication, Wave and Push. Push authentication is targeted to a 
specific user, where Wave authentication is performed by displaying a WaveCode that can be 
scanned by a user. Once authenticated, the Service Provider will be informed of the user's 
username.
  * [Wave authentication](#WaveAuth)
  * [Push authentication](#PushAuth)
### Advanced Features  

Payload is a feature where a Service Provider can encrypt and send data to a user's device
for storage via an authentication or at enrolment, and then retrieved from the user's device when 
required via an authentication. Each individual payload has a maximum size of 4k bytes.
Ideally, this would be used by a Service Provider, such that any private or sensitive user data that the 
Service Provider requires could be held at rest on the user's own device rather than held collectively at
the Service Provider's storage where the consequences of a hack are far further reaching.
Examples of where payload could be used include credit card payment details for a regularly used
service, address details or other personally identifying details.
  * [Payload](#Payload)
## Cipherise Functionality

  * [Querying a Cipherise server](#QueryCS)
  * [Creating new services](#NewService)
  * [Revoking services](#RevokeService)
  * [Enrolling a user to a service](#EnrolUser)
  * [Revoking users from a service](#RevokeUser)
  * [Wave authentication](#WaveAuth)
  * [Push authentication](#PushAuth)
  * [Payload](#Payload)

> **_TIP_**
> Please see the complete end to end [Example Application](https://developer.cipherise.com/resources/docs/dotnet/articles/sample.html).

### <a name="QueryCS"></a>Querying a Cipherise server
A Cipherise server can be queried for information using [ICipheriseServiceProvider.Info()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Info_Cipherise_ICipheriseInfo_):

```CS
static async Task<string> CipheriseExample(string strCipheriseServer)
{
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer);

    //Server Version
    ServerInfo SI = new ServerInfo();
    if (false == await SP.Info(SI))
        return "Cipherise failed during Info()";

    return "Cipherise Info() completed successfully.";
}

private class CSError : ICipheriseError
{
    public string m_strCipheriseError { get; set; }

    //ICipheriseError
    public void CipheriseError(string strError)
    {
        m_strCipheriseError = strError;
    }
}

private class ServerInfo : CSError, ICipheriseInfo
{
    //ICipheriseInfo
    public void ServerVersion(string strServerVersion)
    {
        Console.WriteLine("ServerVersion: {0}", strServerVersion);
    }
}
```
### <a name="NewService"></a>Creating new services
The first step to integrating your Service Provider with Cipherise is to register a service. 
A service can be registered using [ICipheriseServiceProvider.Register()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Register_System_String_Cipherise_ICipheriseError_):

```CS
static async Task<string> CipheriseExample(string strCipheriseServer)
{
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer);

    /////////////////////////////////////////////////////////
    //Register a service provider
    if (false == await SP.Register("My New Cipherise Service Provider"))
        return "Cipherise failed during Register()";

    string strServiceID = SP.GetServiceProviderID();
    Console.WriteLine("Service Provider created with ID: {0}", strServiceID);

    return "Cipherise Register() completed successfully.";
}
```

> **_NOTE_**
> It is the Service Providers responsibility to persist the service ID. To reuse the same service pass its service ID to
> [CreateServiceProvider()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.CipheriseSP.html#Cipherise_CipheriseSP_CreateServiceProvider_System_String_System_String_System_String_System_Int32_).
### <a name="RevokeService"></a>Revoking services
A Service Provider can revoke any services it owns by calling
[ICipheriseServiceProvider.Revoke()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Revoke_Cipherise_ICipheriseError_).
This may be done when, for example, a Cipherise integration is uninstalled.

```CS
static async Task<string> CipheriseExample(string strCipheriseServer, string strServiceID)
{
    //Pass in an existing Service ID:
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer, strServiceID);

    /////////////////////////////////////////////////////////
    //Revoke a service provider.
    if (false == await SP.Revoke())
        return "Cipherise failed during Revoke()";

    return "Cipherise Revoke() completed successfully.";
}
```

> **_WARNING_**
> Revoking a service will disable it and as such deny future enrolments and authentications.
### <a name="EnrolUser"></a>Enrolling a user to a service
To enrol a user into a service the follow steps need to occur:

1. The Service Provider calls 
[ICipheriseServiceProvider.EnrolUser()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_EnrolUser_Cipherise_ICipheriseEnrolUser_).

2. The SDK informs the Service Provider via
[ICipheriseEnrolUser::DisplayWaveCode()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_DisplayWaveCode_System_String_)
that an enrolment WaveCode is ready to be presented to the user.

3. The user scans the WaveCode with the Cipherise App.

4. The SDK informs the Service Provider via
[ICipheriseEnrolUser::DisplayIdenticon()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_DisplayIdenticon_System_String_)
that an identicon is ready to be presented to the user.

5. The Service Provider asks the user to confirm that the identicon presented on their device matches the one from step 4. If it does match
[ICipheriseEnrolUser::DisplayIdenticon()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_DisplayIdenticon_System_String_)
should return true, otherwise false to cancel the enrolment.

6. The SDK informs the Service Provider via
[ICipheriseEnrolUser::Enrolment()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_Enrolment_System_Boolean_System_String_System_String_)
whether the enrolment was successful.

The above steps can be shown here:
```CS
static async Task<string> CipheriseExample(string strCipheriseServer, string strServiceID, string strUserName)
{
    //Pass in an existing Service ID:
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer, strServiceID);

    //Enrol a user
    EnrolUser EU = new EnrolUser(strUserName);
    if (false == await SP.EnrolUser(EU))
        return "Cipherise failed during EnrolUser()";

    return "Cipherise EnrolUser() completed successfully.";
}

private class CSError : ICipheriseError
{
    public string m_strCipheriseError { get; set; }

    //ICipheriseError
    public void CipheriseError(string strError)
    {
        m_strCipheriseError = strError;
    }
}

class CSPayload : CSError, ICipherisePayload
{
    //ICipherisePayload
    public void PayloadToSend(ref KeyValuePairs kvpSet, ref string[] astrGetKeys)
    {
        //Payload to send to the Cipherise App.
    }

    //ICipherisePayload
    public bool PayloadResponseFromApp(KeyValuePairs kvpGet)
    {
        //Payload retrieved from the Cipherise App.
        //Verify the data in kvpGet.
        return true;
    }
}

private class EnrolUser : CSPayload, ICipheriseEnrolUser
{
    public EnrolUser(string strUserName)
    {
        m_strUserName = strUserName;
    }

    private string m_strUserName;

    public string GetUserName()
    {
        return m_strUserName;
    }

    public bool DisplayWaveCode(string strWaveCodeURL)
    {
        //A real Service provider would display the WaveCode located at: strWaveCodeURL
        Console.WriteLine("Browse to this URL and scan the WaveCode: {0}", strWaveCodeURL);
        return true;
    }

    public bool DisplayIdenticon(string strIdenticonURL)
    {
        //A real Service provider would display the identicon located at: strIdenticonURL
        Console.WriteLine("Browse to this URL and verify the identicon: {0}", strIdenticonURL);
        Console.WriteLine("Does it match the identicon displayed on your phone/device,  Y/N?");

        return GetChar("YN") == 'Y';
    }

    public bool DisplayDirectURL(string strDirectURL)
    {
        //A real Service provider would display a button with the link pointing to : strDirectURL
        //This is only required if being shown on a device where the Cipherise App is installed.
        //If not, then the URL can be ignored.
        Console.WriteLine("Direct enrolment: cipherise://?directEnrolURL={0}", strDirectURL);
        return true;
    }

    public void Enrolment(bool bConfirmed, string strUserName, string strDeviceID)
    {
        if (bConfirmed)
            Console.WriteLine("User '{0}' was enrolled on device with an ID of: {1}", strUserName, strDeviceID);
        else
            Console.WriteLine("User enrolment failed!");
    }

    public bool CanContinuePolling()
    {
        return true;
    }

    public int GetPollTimeInMilliseconds()
    {
        return 0;  //Default = 0, LongPoll = -1
    }

    public bool RepeatOnTimeout()
    {
        return true;
    }
}
```
### <a name="RevokeUser"></a>Revoking users from a service
A Service Provider can revoke a user by calling
[ICipheriseServiceProvider.RevokeUser()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_RevokeUser_Cipherise_ICipheriseRevokeUser_).
This could be called for a number of reasons. For example, a user leaves an organisation and is no 
longer authorised for access. To regain access, the user must re-enrol.

```CS
static async Task<string> CipheriseExample(string strCipheriseServer, string strServiceID, string strUserName)
{
    //Pass in an existing Service ID:
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer, strServiceID);

    //Revoke a user
    RevokeUser RU = new RevokeUser(strUserName, null);
    if (false == await SP.RevokeUser(RU))
        return "Cipherise failed during RevokeUser()";

    return "Cipherise RevokeUser() completed successfully.";
}

private class CSError : ICipheriseError
{
    public string m_strCipheriseError { get; set; }

    //ICipheriseError
    public void CipheriseError(string strError)
    {
        m_strCipheriseError = strError;
    }
}

class RevokeUser : CSError, ICipheriseRevokeUser
{
    public RevokeUser(string strUserName, string[] astrDeviceIDs)
    {
        m_strUserName = strUserName;
        m_astrDeviceIDs = astrDeviceIDs;
    }

    private string m_strUserName;
    public string GetUserName()
    {
        return m_strUserName;
    }

    private string[] m_astrDeviceIDs;
    public string[] GetDeviceIDs()
    {
        return m_astrDeviceIDs;
    }

    private string[] m_astrInvalidDeviceIDs;
    public void SetInvalidIDs(string[] astrInvalidDeviceIDsIn)
    {
        m_astrInvalidDeviceIDs = astrInvalidDeviceIDsIn;
    }

    public string[] GetInvalidDeviceIDs()
    {
        return m_astrInvalidDeviceIDs;
    }

    public int GetInvalidDeviceIDCount()
    {
        return m_astrInvalidDeviceIDs == null ? 0 : m_astrInvalidDeviceIDs.Length;
    }
}
```

> **_WARNING_**
> Revoking a user will deny any future authentications to the service. The user must re-enrol to the service to allow authentications.
### <a name="WaveAuth"></a>Wave authentication
Wave authentication is where the user 'waves' their device over a WaveCode to trigger
the authentication process.

The following steps need to occur in a Wave Authentication:

1. The Service Provider calls 
[ICipheriseServiceProvider.Authenticate()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Authenticate_Cipherise_ICipheriseAuthenticate_), 
passing in an instance to [ICipheriseAuthenticateWave](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticateWave.html).

2. The SDK informs the Service Provider via
[ICipheriseAuthenticateWave::DisplayWaveCode()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticateWave.html#Cipherise_ICipheriseAuthenticateWave_DisplayWaveCode_System_String_)
that an authorisation WaveCode is ready to be presented to the user.

3. The user scans the WaveCode with the Cipherise App.

4. Methods of 
[ICipheriseAuthenticate](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticate.html)
are called by the SDK to determine the type of authentication required by the Service Provider.

5. The user responds to the authentication notification on their device and solves the 
authentication challenge.

6. When the authentication has completed the SDK calls
[ICipheriseAuthenticate.Authenticated()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticate.html#Cipherise_ICipheriseAuthenticate_Authenticated_Cipherise_CipheriseAuthenticationResponse_System_String_System_String_System_String_)
to instruct the Service Provider of the authentication result. 

```CS
static async Task<string> CipheriseExample(string strCipheriseServer, string strServiceID)
{
    //Pass in an existing Service ID:
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer, strServiceID);

    //Wave Authentication
    AuthenticateBase Auth = new WaveAuth();
    if (false == await SP.Authenticate(Auth))
        return "Cipherise failed during Authenticate()";

    CipheriseAuthenticationResponse eResponse = Auth.GetResponse();

    Console.WriteLine();
    if (eResponse == CipheriseAuthenticationResponse.eCAR_Accept)
        Console.WriteLine("User '{0}' accepted authentication on device '{1}'.", Auth.GetUserName(), Auth.GetDeviceID());
    else if (eResponse == CipheriseAuthenticationResponse.eCAR_Cancel)
        Console.WriteLine("Authentication was cancelled!");
    else if (eResponse == CipheriseAuthenticationResponse.eCAR_Report)
        Console.WriteLine("Authentication was reported!");

    return "Cipherise Authenticate(Wave) completed successfully.";
}

private class CSError : ICipheriseError
{
    public string m_strCipheriseError { get; set; }

    //ICipheriseError
    public void CipheriseError(string strError)
    {
        m_strCipheriseError = strError;
    }
}

class CSPayload : CSError, ICipherisePayload
{
    //ICipherisePayload
    public void PayloadToSend(ref KeyValuePairs kvpSet, ref string[] astrGetKeys)
    {
        //Payload to send to the Cipherise App.
    }

    //ICipherisePayload
    public bool PayloadResponseFromApp(KeyValuePairs kvpGet)
    {
        //Payload retrieved from the Cipherise App.
        //Verify the data in kvpGet.
        return true;
    }
}

private class AuthenticateBase : CSPayload, ICipheriseAuthenticate
{
    //ICipheriseAuthenticate
    public CipheriseAuthenticationType GetAuthenticationType()
    {
        return CipheriseAuthenticationType.eCAT_AuthApproval;
    }

    //ICipheriseAuthenticate
    public string GetNotificationMessage()
    {
        return "My Notification Messsage!";
    }

    //ICipheriseAuthenticate
    public string GetAuthenticationMessage()
    {
        return "My Authentication Messsage!";
    }

    //ICipheriseAuthenticate
    public string GetBrandingMessage()
    {
        return "My Branding Messsage!";
    }

    public void Authenticated(CipheriseAuthenticationResponse eResponse, string strUserName, string strDeviceName, string strDeviceID)
    {
        m_strUserName = strUserName;
        m_strDeviceName = strDeviceName;
        m_strDeviceID = strDeviceID;

        m_eResponse = eResponse;
    }

    private CipheriseAuthenticationResponse m_eResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
    public CipheriseAuthenticationResponse GetResponse()
    {
        return m_eResponse;
    }

    //ICipheriseAuthenticate
    public int GetPollTimeInMilliseconds()
    {
        return 0;   //0 for default value, -1 for Longpolling.
    }

    //ICipheriseAuthenticate
    public bool CanContinuePolling()
    {
        return true;
    }

    private string m_strUserName;
    public string GetUserName()
    {
        return m_strUserName;
    }

    private string m_strDeviceName;
    public string GetDeviceName()
    {
        return m_strDeviceName;
    }

    private string m_strDeviceID;
    public string GetDeviceID()
    {
        return m_strDeviceID;
    }

    protected void SetUserAuth(string strUserName, string strDeviceID)
    {
        m_strUserName = strUserName;
        m_strDeviceID = strDeviceID;
    }

    //ICipheriseAuthenticate
    public void WaitingForCipheriseApp()
    {
        Console.WriteLine();
        Console.WriteLine("Please check your Cipherise App.");
    }

    //ICipheriseAuthenticate
    public void CipheriseAppDetails(string strUserName)
    {
        Console.WriteLine();
        Console.WriteLine("Cipherise App user is: {0}", strUserName);
    }

    //ICipheriseAuthenticate
    public virtual bool RepeatOnTimeout()
    {
        return true;
    }
}

private class WaveAuth : AuthenticateBase, ICipheriseAuthenticateWave
{
    //ICipheriseAuthenticateWave
    public bool DisplayWaveCode(string strWaveCodeURL)
    {
        //A real Service provider would display the WaveCode located at: strWaveCodeURL
        Console.WriteLine();
        Console.WriteLine("Browse to this URL and scan the WaveCode: {0}", strWaveCodeURL);
        return true;
    }

    //ICipheriseAuthenticateWave
    public bool DisplayDirectURL(string strDirectURL)
    {
        //A real Service provider would display a button with the link pointing to : strDirectURL
        //This is only required if being shown on a device where the Cipherise App is installed. 
        //If not, then the URL can be ignored.
        Console.WriteLine();
        Console.WriteLine("Direct Authentication: cipherise://?directAuthURL={0}", strDirectURL);
        return true;
    }

    //ICipheriseAuthenticateWave
    public string GetRedirectURL()
    {
        //Default behaviour.
        return null;
    }
}
```
### <a name="PushAuth"></a>Push authentication
Push authentication is a Cipherise authentication that is sent to a particular user's device. This 
can only be used when the Service wants to target a specific user and the username and deviceid are
known for that user. Ideally, this is suited for workflow related cases, such as authorising a 
banking transaction (targeted user is the owner of the transferring account), or seeking permission
for a privileged activity (targeted user is the supervisor of the user seeking permission).

The following steps need to occur in a Push Authentication:

1. The Service Provider looks up the username (the name the user was enrolled to Cipherise as) of the authenticating user.

2. The Service Provider calls 
[ICipheriseServiceProvider.RetrieveUsersDevices](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_RetrieveUsersDevices_Cipherise_ICipheriseDevice_)
to determine the users device ID to send the authentication.
Note that there can be more than one device registered to a user. In this situation, the Service Provider will need to determine which one(s) to 
send the authentication to.

3. The Service Provider calls 
[ICipheriseServiceProvider.Authenticate()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_Authenticate_Cipherise_ICipheriseAuthenticate_), 
passing in an instance to [ICipheriseAuthenticatePush](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticatePush.html).

4. Methods of 
[ICipheriseAuthenticate](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticate.html)
are called by the SDK to determine the type of authentication required by the Service Provider.

5. The user responds to the authentication notification on their device and solves the 
authentication challenge.

6. When the authentication has completed the SDK calls
[ICipheriseAuthenticate.Authenticated()](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipheriseAuthenticate.html#Cipherise_ICipheriseAuthenticate_Authenticated_Cipherise_CipheriseAuthenticationResponse_System_String_System_String_System_String_)
to instruct the Service Provider of the authentication result.

```CS
static async Task<string> CipheriseExample(string strCipheriseServer, string strServiceID, string strUserName)
{
    //Pass in an existing Service ID:
    ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer, strServiceID);

    //Query a users devices
    DeviceData Device = new DeviceData(strUserName);
    if (false == await SP.RetrieveUsersDevices(Device))
        return "Cipherise failed during RetrieveUsersDevices()";

    //Push Authentication
    AuthenticateBase Auth = new PushAuth(strUserName, Device.GetDeviceID());
    if (false == await SP.Authenticate(Auth))
        return "Cipherise failed during Authenticate()";

    CipheriseAuthenticationResponse eResponse = Auth.GetResponse();

    Console.WriteLine();
    if (eResponse == CipheriseAuthenticationResponse.eCAR_Accept)
        Console.WriteLine("User '{0}' accepted authentication on device '{1}'.", Auth.GetUserName(), Auth.GetDeviceID());
    else if (eResponse == CipheriseAuthenticationResponse.eCAR_Cancel)
        Console.WriteLine("Authentication was cancelled!");
    else if (eResponse == CipheriseAuthenticationResponse.eCAR_Report)
        Console.WriteLine("Authentication was reported!");

    return "Cipherise Authenticate(Push) completed successfully.";
}

private class CSError : ICipheriseError
{
    public string m_strCipheriseError { get; set; }

    //ICipheriseError
    public void CipheriseError(string strError)
    {
        m_strCipheriseError = strError;
    }
}

class CSPayload : CSError, ICipherisePayload
{
    //ICipherisePayload
    public void PayloadToSend(ref KeyValuePairs kvpSet, ref string[] astrGetKeys)
    {
        //Payload to send to the Cipherise App.
    }

    //ICipherisePayload
    public bool PayloadResponseFromApp(KeyValuePairs kvpGet)
    {
        //Payload retrieved from the Cipherise App.
        //Verify the data in kvpGet.
        return true;
    }
}

private class AuthenticateBase : CSPayload, ICipheriseAuthenticate
{
    //ICipheriseAuthenticate
    public CipheriseAuthenticationType GetAuthenticationType()
    {
        return CipheriseAuthenticationType.eCAT_AuthApproval;
    }

    //ICipheriseAuthenticate
    public string GetNotificationMessage()
    {
        return "My Notification Messsage!";
    }

    //ICipheriseAuthenticate
    public string GetAuthenticationMessage()
    {
        return "My Authentication Messsage!";
    }

    //ICipheriseAuthenticate
    public string GetBrandingMessage()
    {
        return "My Branding Messsage!";
    }

    public void Authenticated(CipheriseAuthenticationResponse eResponse, string strUserName, string strDeviceName, string strDeviceID)
    {
        m_strUserName = strUserName;
        m_strDeviceName = strDeviceName;
        m_strDeviceID = strDeviceID;

        m_eResponse = eResponse;
    }

    private CipheriseAuthenticationResponse m_eResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
    public CipheriseAuthenticationResponse GetResponse()
    {
        return m_eResponse;
    }

    //ICipheriseAuthenticate
    public int GetPollTimeInMilliseconds()
    {
        return 0;   //0 for default value, -1 for Longpolling.
    }

    //ICipheriseAuthenticate
    public bool CanContinuePolling()
    {
        return true;
    }

    private string m_strUserName;
    public string GetUserName()
    {
        return m_strUserName;
    }

    private string m_strDeviceName;
    public string GetDeviceName()
    {
        return m_strDeviceName;
    }

    private string m_strDeviceID;
    public string GetDeviceID()
    {
        return m_strDeviceID;
    }

    protected void SetUserAuth(string strUserName, string strDeviceID)
    {
        m_strUserName = strUserName;
        m_strDeviceID = strDeviceID;
    }

    //ICipheriseAuthenticate
    public void WaitingForCipheriseApp()
    {
        Console.WriteLine();
        Console.WriteLine("Please check your Cipherise App.");
    }

    //ICipheriseAuthenticate
    public void CipheriseAppDetails(string strUserName)
    {
        Console.WriteLine();
        Console.WriteLine("Cipherise App user is: {0}", strUserName);
    }

    //ICipheriseAuthenticate
    public virtual bool RepeatOnTimeout()
    {
        return true;
    }
}

private class PushAuth : AuthenticateBase, ICipheriseAuthenticatePush
{
    public AuthPush(string strUserName, string strDeviceID)
    {
        SetUserAuth(strUserName, strDeviceID);
    }

    //ICipheriseAuthenticate
    public override bool RepeatOnTimeout()
    {
        return false;
    }
}

private class DeviceData : CSError, ICipheriseDevice
{
    public DeviceData(string strUsername)
    {
        m_strUserName = strUsername;
    }

    private string m_strUserName;

    //ICipheriseDevice
    public string GetUserName()
    {
        return m_strUserName;
    }

    //ICipheriseDevice
    public bool IncludeUnauthorisedDevices()
    {
        return false;
    }

    //ICipheriseDevice
    public bool DeviceInfo(string strDeviceName, string strDeviceID, bool bAuthorised)
    {
        Console.WriteLine("Device with ID {0} has the name: {1} {2}", strDeviceID, strDeviceName, bAuthorised ? "" : " (is not authorised!)");
        if (bAuthorised)
            m_strDeviceID = strDeviceID;  //Store the last device ID, required for Push Authentication.
        ++m_iDeviceCount;
        return true; //Continue getting more devices.
    }

    private int m_iDeviceCount = 0;
    public int GetCount()
    {
        return m_iDeviceCount;
    }

    private string m_strDeviceID = null;
    public string GetDeviceID()
    {
        return m_strDeviceID;
    }
}
```


### <a name="Payload"></a>Payload

Payload data can be supplied to the user's device during 
[enrolment](#EnrolUser)
and supplied and fetched during 
[push](#PushAuth)
and 
[wave](#WaveAuth)
authentication. 

Payload data is arbitrary and is controlled by the Service Provider. 
All payload data is internally encrypted when supplied to and fetched from the users device.

Payload data is accessed by declaring a class that implements the 
[ICipherisePayload](https://developer.cipherise.com/resources/docs/dotnet/api/Cipherise.ICipherisePayload.html)
interface: 
```CS
class CSPayload : CSError, ICipherisePayload
{
    //ICipherisePayload
    public void PayloadToSend(ref KeyValuePairs kvpSet, ref string[] astrGetKeys)
    {
        //Payload to send to the Cipherise App.
        if (kvpSet == null)
            kvpSet = new KeyValuePairs();
        kvpSet.Add("Authentication",   "Cipherise is more than just authentication!");
        kvpSet.Add("Getting started?", "Visit developer.cipherise.com");
    }

    //ICipherisePayload
    public bool PayloadResponseFromApp(KeyValuePairs kvpGet)
    {
        //Payload retrieved from the Cipherise App.

        //Verify the data in kvpGet.
        if (kvpGet.Count != 2)
            return false;

        return true;
    }
}
```