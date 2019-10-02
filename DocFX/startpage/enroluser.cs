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