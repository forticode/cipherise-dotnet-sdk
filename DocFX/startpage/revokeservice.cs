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