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