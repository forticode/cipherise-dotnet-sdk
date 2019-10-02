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