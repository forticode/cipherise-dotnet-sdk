using Cipherise;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

using KeyValuePairs = System.Collections.Generic.Dictionary<string, string>;

namespace CipheriseExample
{
    class Program
    {
        static void Main(string[] args)
        {
            bool bUsage = false;
            bool bVerbose = false;
            int iArgIndex = 0;

            if ((args.Length == 0) || (args.Length > 2))
                bUsage = true;
            else if ((args[iArgIndex] == "-verbose") || (args[iArgIndex] == "-v"))
            {
                bVerbose = true;
                ++iArgIndex;
            }
            else if (args.Length != iArgIndex + 1)
                bUsage = true;

            if (bUsage)
                Console.WriteLine("\nInvalid usage.  \n\tCipheriseExample [-verbose|-v] <URL to Cipherise Server>");
            else
            {
                string strCipheriseServer = "https://my.cipherise.server.com";
                strCipheriseServer = args[iArgIndex];
                Console.WriteLine("\nConnecting to Cipherise Server: {0}", strCipheriseServer);

                if (Uri.IsWellFormedUriString(strCipheriseServer, UriKind.Absolute))
                {
                    try
                    {
                        Task<string> T = CipheriseExample(strCipheriseServer, bVerbose);
                        T.Wait();

                        Console.WriteLine();
                        Console.WriteLine(T.Result);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("\nException caught: {0}", e.Message);
                    }
                }
                else
                    Console.WriteLine("\nInvalid Cipherise URL: {0}", strCipheriseServer);
            }
        }

        static async Task<string> CipheriseExample(string strCipheriseServer,  bool bVerbose)
        {
            Trace.Listeners.Add(new TextWriterTraceListener(Console.Out));
            Cipherise.CipheriseSP.SetTraceLevel(bVerbose ? TraceLevel.Verbose : TraceLevel.Error);

            ICipheriseServiceProvider SP = Cipherise.CipheriseSP.CreateServiceProvider(strCipheriseServer);

            /////////////////////////////////////////////////////////
            //Server Version
            ServerInfo SI = new ServerInfo();
            if (false == await SP.Info(SI))
            {
                Console.WriteLine("\nInfo() error: {0}", SI.m_strCipheriseError);
                return "Cipherise failed during Info()";
            }

            /////////////////////////////////////////////////////////
            //Register a service provider
            // This should happen only once.
            if (false == await SP.Register("My New Cipherise Service Provider"))
                return "Cipherise failed during Register()";

            string strServiceID = SP.GetServiceProviderID();
            Console.WriteLine("Service Provider created with ID: {0}", strServiceID);

            /////////////////////////////////////////////////////////
            //Verify registration of the service provider.
            //  Uses the current Service Id. 
            //  One could call SP.SetPreviousSessionID( otherID ) to change the Service Id. 
            if (false == await SP.IsRegistered())
                return "Cipherise failed during IsRegistered()";

            /////////////////////////////////////////////////////////
            //Set a user name.
            const string strUserName = "MyUserName";

            /////////////////////////////////////////////////////////
            //Enrol a user
            EnrolUser EU = new EnrolUser(strUserName);
            if (false == await SP.EnrolUser(EU))
                return "Cipherise failed during EnrolUser()";

            /////////////////////////////////////////////////////////
            //Query a users devices
            DeviceData Device = new DeviceData(strUserName);
            if (false == await SP.RetrieveUsersDevices(Device))
                return "Cipherise failed during RetrieveUsersDevices()";

            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("P) Push Authentication");
                Console.WriteLine("W) Wave  Authentication");
                Console.WriteLine("X) Exit");
                Console.WriteLine("---------------------------");
                Console.Write("Press P, W or X: ");
                char ch = GetChar("PWX");

                if (ch == 'X')
                {
                    Console.WriteLine();
                    Console.WriteLine();
                    break;
                }

                CipheriseAuthenticationResponse eResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
                string strAuthUserName = strUserName;
                string strAuthDeviceID = Device.GetDeviceID();

                AuthenticateBase Auth = null;
                if (ch == 'P')
                {
                    /////////////////////////////////////////////////////////
                    //Send an authentication request to the users device.
                    Console.WriteLine();
                    Console.WriteLine("Sending an authentication request to the device.  Please acknowledge it...");
                    Auth = new AuthPush(strAuthUserName, strAuthDeviceID);
                }

                if (ch == 'W')
                {
                    /////////////////////////////////////////////////////////
                    //Start a Wave authentication request, which will give the
                    //  user a WaveCode to scan with their phone/device.
                    Auth = new WaveAuth();
                }

                if (Auth != null)
                {
                    if (false == await SP.Authenticate(Auth))
                        return "Cipherise failed during Authenticate()";

                    eResponse = Auth.GetResponse();
                }

                Console.WriteLine();
                if (eResponse == CipheriseAuthenticationResponse.eCAR_Accept)
                    Console.WriteLine("User '{0}' accepted authentication on device '{1}'.", Auth.GetUserName(), Auth.GetDeviceID());
                else if (eResponse == CipheriseAuthenticationResponse.eCAR_Cancel)
                    Console.WriteLine("Authentication was cancelled!");
                else if (eResponse == CipheriseAuthenticationResponse.eCAR_Report)
                    Console.WriteLine("Authentication was reported!");
            }

            /////////////////////////////////////////////////////////
            //Revoke a users device from using this service provider.
            // The user will no long be able to use the device ID to authenticate.
            // Re-enrolling the user and their device will rectivate the device for this service provider.
            // Pass in an empty device ID list to revoke all devices for a user.
            RevokeUser RU = new RevokeUser(strUserName, new string[1] { Device.GetDeviceID() });
            if (false == await SP.RevokeUser(RU))
                return "Cipherise failed during RevokeUser()";
            if (RU.GetInvalidDeviceIDCount() > 0)
                return "Cipherise failed during RevokeUser() - contained a invalid ID";

            Console.WriteLine("User and device were revoked.");

            /////////////////////////////////////////////////////////
            //Revoke a service provider.
            // This should happen only once.
            // The service ID will no longer be usable.
            // Users will no longer be able to authenticate.
            if (false == await SP.Revoke())
                return "Cipherise failed during Revoke()";

            Console.WriteLine("Service Provider was revoked.");

            return "Cipherise completed successfully.";
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

        class CSPayload : CSError, ICipherisePayload
        {
            //ICipherisePayload
            public void PayloadToSend(ref KeyValuePairs kvpSet, ref string[] astrGetKeys)
            {
                //Payload to send to the Cipherise App.
                if (kvpSet == null)
                    kvpSet = new KeyValuePairs();
                kvpSet.Add("PL_1", "PL_one");
                kvpSet.Add("PL_2", "PL_two");
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
                //This is only required if being shown on a device where the Cipherise App is installed. If not, then the URL can be ignored.
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

        private class DeviceData : CSError, ICipheriseDevice
        {
            public DeviceData(string strUsername, bool bUnauthorised = false)
            {
                m_strUserName = strUsername;
                m_bUnauthorised = bUnauthorised;
            }

            private string m_strUserName;
            public string GetUserName()
            {
                return m_strUserName;
            }

            private bool m_bUnauthorised = false;
            public bool IncludeUnauthorisedDevices()
            {
                return m_bUnauthorised;
            }

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

        private class AuthenticateBase : CSPayload, ICipheriseAuthenticate
        {
            public CipheriseAuthenticationType GetAuthenticationType()
            {
                return CipheriseAuthenticationType.eCAT_AuthApproval;
            }

            public string GetNotificationMessage()
            {
                return "My Notification Messsage!";
            }

            public string GetAuthenticationMessage()
            {
                return "My Authentication Messsage!";
            }

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

            public int GetPollTimeInMilliseconds()
            {
                return 0;   //0 for default value, -1 for Longpolling.
            }

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
            public void WaitingForCipheriseApp()
            {
                Console.WriteLine();
                Console.WriteLine("Please check your Cipherise App.");
            }

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

        private class AuthPush : AuthenticateBase, ICipheriseAuthenticatePush
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

        private class WaveAuth : AuthenticateBase, ICipheriseAuthenticateWave
        {

            public bool DisplayWaveCode(string strWaveCodeURL)
            {
                //A real Service provider would display the WaveCode located at: strWaveCodeURL
                Console.WriteLine();
                Console.WriteLine("Browse to this URL and scan the WaveCode: {0}", strWaveCodeURL);
                return true;
            }

            public bool DisplayDirectURL(string strDirectURL)
            {
                //A real Service provider would display a button with the link pointing to : strDirectURL
                //This is only required if being shown on a device where the Cipherise App is installed. If not, then the URL can be ignored.
                Console.WriteLine();
                Console.WriteLine("Direct Authentication: cipherise://?directAuthURL={0}", strDirectURL);
                return true;
            }

            public string GetRedirectURL()
            {
                //Default behaviour.
                return null;
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

        static char GetChar(string strValidKeys, bool bShow = false, bool bUpperCase = true)
        {
            if (bUpperCase)
                strValidKeys = strValidKeys.ToUpper();

            while (true)
            {
                char ch = Console.ReadKey(bShow == false).KeyChar;

                if (bUpperCase)
                    ch = Char.ToUpper(ch);

                if (strValidKeys.Contains(ch))
                    return ch;
            }
        }

    }
}
