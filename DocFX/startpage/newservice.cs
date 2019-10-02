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