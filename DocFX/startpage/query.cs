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