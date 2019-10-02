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