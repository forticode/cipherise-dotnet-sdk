using System;
using System.Diagnostics;
using System.Collections.Generic;       //List<T>
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Threading.Tasks;

using Org.BouncyCastle.Crypto;

using KeyValuePairs    = System.Collections.Generic.Dictionary<string, string>;
using NumberDictionary = System.Collections.Generic.Dictionary<string, string>;
using Cipherise.Common;

namespace Cipherise
{
    //////////////////////////////////////////////////////////////////////////////////////////

    /// <summary>
    /// The access point to the Cipherise Service Provider. Provides the means of 
    /// instantiating a <see cref="ICipheriseServiceProvider"/>, used to interact 
    /// with a Cipherise Server.
    /// </summary>
    public static class CipheriseSP
    {
        private static TraceSwitch s_CipheriseSwitch = new TraceSwitch("CipheriseSDK", "Cipherise SDK logging", "1");

        /// <summary>
        /// Sets the debugging trace level.
        /// </summary>
        /// <param name="eLevel">The level to set.</param>
        public static void SetTraceLevel(TraceLevel eLevel)
        {
            s_CipheriseSwitch.Level = eLevel;
        }

        /// <summary>
        /// Returns the current debugging trace level.
        /// </summary>
        /// <returns>The current trace level.</returns>
        public static TraceLevel GetTraceLevel()
        {
            return s_CipheriseSwitch.Level;
        }

        /// <summary>
        /// Initial version of the SDK
        /// </summary>
        public const int SDK_VERSION_1      = 1;
        
        /// <summary>
        /// Version 2 introduced Direct Enrolment and Authentication - useful for the scenario 
        /// that enrolment or authentication is required on the same device that is performing 
        /// the Cipherise function.
        /// </summary>
        public const int SDK_VERSION_2      = 2;

        /// <summary>
        /// Version 3 introduced Bi-Directional authentication - allows the application to be certain
        /// of the Service Provider, in addition to the Service Provider validating the end user.
        /// </summary>
        public const int SDK_VERSION_3      = 3;

        /// <summary>
        /// Version 6.000 introduced DocFX.
        /// </summary>
        public const int SDK_VERSION_6_000      = 6000;

        /// <summary>
        /// Constant for intent to use latest SDK, irrespective of version. This is the default option.
        /// </summary>
        public const int SDK_VERSION_LATEST = SDK_VERSION_6_000;

        /// <summary>
        /// Creates an instance of a Cipherise interface, used to interact with a Cipherise Server.
        /// </summary>
        /// <param name="strCipheriseServer">The server address, for example "https://cipherise.mycompany.com"</param>
        /// <param name="strServiceProviderID">A previously registered service provider ID. 
        /// Leave empty when a new service is required. Otherwise, the previously registered identifier.
        /// Note, if a new service is created, previous enrolments won't be accessible.</param>
        /// <param name="strKeyLocation">The file location to where the Services private key is stored. 
        /// !IMPORTANT! Must be a secure location. 
        /// Note that this is optional, default is to use the current working directory.</param>
        /// <param name="iSDKVersion">The maximum SDK version to support. Use <see cref="SDK_VERSION_LATEST"/>
        /// to use the latest SDK version.</param>
        /// <returns>An instance of a Cipherise interface, used to interact with a Cipherise Server.</returns>
        public static ICipheriseServiceProvider CreateServiceProvider(string strCipheriseServer, string strServiceProviderID = "", string strKeyLocation = "", int iSDKVersion = SDK_VERSION_LATEST)
        {
            return new ServiceProvider(iSDKVersion, strCipheriseServer, strServiceProviderID, strKeyLocation);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    internal class ServiceProvider : ICipheriseServiceProvider
    {
        private int    m_iSDKVersion;
        private string m_strCipheriseServer;
        private string m_strServiceProviderID;
        private string m_strKeyLocation;
        private string m_strSessionID;

        CipheriseBouncyCastle m_BC;

        public ServiceProvider(int iSDKVersion, string strCipheriseServer, string strServiceProviderID = "", string strKeyLocation = "")
        {
            m_iSDKVersion          = iSDKVersion;
            m_strCipheriseServer   = strCipheriseServer.Trim(new char[] { ' ', '\\', '/' });
            m_strServiceProviderID = strServiceProviderID;
            m_strKeyLocation       = strKeyLocation;

            m_BC = new CipheriseBouncyCastle();
        }

        //ICipheriseServiceProvider
        public string GetServiceProviderID()
        {
            return m_strServiceProviderID;
        }

        //ICipheriseServiceProvider
        public async Task<bool> Info(ICipheriseInfo InfoCB)
        {
            "Info()".TraceVerbose();

            SPInfoOut InfoOut = await (m_strCipheriseServer + "/info").CipheriseRequest<SPInfoOut>();

            if (InfoOut == null)
                return false;
            if (InfoOut.HasError())
            {
                InfoCB.CipheriseError(InfoOut.GetError());
                return false;
            }

            InfoCB.ServerVersion(InfoOut.strServerVersion);
            return true;
        }

        //ICipheriseServiceProvider
        public async Task<bool> IsRegistered(ICipheriseError CSError = null)
        {
            "IsRegistered()".TraceVerbose();

            if (CSError == null)
                CSError = new CipheriseErrorImple();

            return await InitSession(false, CSError);
        }

        //ICipheriseServiceProvider
        public async Task<bool> Register(string strServiceProviderName, ICipheriseError CSError = null)
        {
            "Register()".TraceVerbose();

            if (string.IsNullOrEmpty(strServiceProviderName))
            {
                "Invalid Service Provider Name.".TraceError();
                return false;
            }

            if (CSError == null)
                CSError = new CipheriseErrorImple();

            if (await InitSession(false, CSError) == true)
            {
                "Already registered!".TraceWarning();
                return false;
            }

            //Generate Keys.
            if (m_BC.GenerateKeyPair() == false)
            {
                "Unable to generate Keys.".TraceError();
                return false;
            }
            string strPubKey;
            if (m_BC.GetPublicKeyAsPEM(out strPubKey) == false)
            {
                "Unable to get public key.".TraceError();
                return false;
            }

            //Send friendly name and Public PEM
            SPRegisterIn RegIn = new SPRegisterIn();
            RegIn.strFriendlyName = strServiceProviderName;
            RegIn.strPublicKey = strPubKey;
            if (RegIn.Validate() == false)
            {
                "Registration Init data is invalid.".TraceWarning();
                return false;
            }

            SPRegisterOut RegOut = await (m_strCipheriseServer + "/sp/create-service/").CipheriseRequest<SPRegisterOut>(HttpStatusCode.Created, RegIn.ToJSON());
            if (RegOut == null)
                return false;
            if (RegOut.HasError())
            {
                CSError.CipheriseError(RegOut.GetError());
                return false;
            }

            m_strServiceProviderID = RegOut.strServiceID;

            if (SaveKeyToFile() == false)
                return false;

            RegOut.strServiceID.TraceVerbose("New ServiceID: ");
            return true;
        }

        //ICipheriseServiceProvider
        public async Task<bool> Revoke(ICipheriseError Err = null)
        {
            "Revoke()".TraceVerbose();
            bool bRet = false;

            if (Err == null)
                Err = new CipheriseErrorImple();

            if (await InitSession(true, Err) == false)
            {
                "Unable to initialise session.".TraceWarning();
            }
            else
            {
                m_strServiceProviderID.TraceVerbose("Revoking ServiceID: ");
                bRet = null != await (m_strCipheriseServer + "/sp/revoke-service/").CipheriseRequest<CipheriseCommon.EmptyResponse>("", m_strSessionID);
            }

            //Delete .Key file
            string strFilename;
            if (GetKeyFilename(true, out strFilename))
                File.Delete(strFilename);

            if (bRet)
            {
                m_strSessionID = null;
                m_strServiceProviderID = null;
            }
            return bRet;
        }

        //Internal Enrol helper methods (EnrolUserInit, EnrolUserValidate, EnrolUserConfirm), use to be in ICipheriseServiceProvider.
        public async Task<EnrolUserReturn> EnrolUserInit(string strUserName)
        {
            "EnrolUserInit()".TraceVerbose();

            EnrolUserReturn retEUR = new EnrolUserReturn();

            if (string.IsNullOrEmpty(strUserName))
                return retEUR;

            //Init Session
            {
                CipheriseErrorImple CSError = new CipheriseErrorImple();
                if (await InitSession(true, CSError) == false)
                {
                    "Unable to initialise session.".TraceWarning();
                    retEUR.m_strCipheriseError = CSError.GetError();
                    return retEUR;
                }
            }

            //Enrol User/Device  Init
            {
                EnrolUserInitIn EUInitIn = new EnrolUserInitIn();
                EUInitIn.strUserName = strUserName;
                if (EUInitIn.Validate() == false)
                {
                    "Enrol User Init data is invalid!".TraceWarning();
                    return retEUR;
                }

                EnrolUserInitOut EUInitOut = await (m_strCipheriseServer + "/sp/enrol-user").CipheriseRequest<EnrolUserInitOut>(EUInitIn.ToJSON(), m_strSessionID);
                if (null == EUInitOut)
                {
                    "Enrol User Init failed!".TraceError();
                    return retEUR;
                }
                if (EUInitOut.HasError())
                {
                    retEUR.m_strCipheriseError = EUInitOut.GetError();
                    return retEUR;
                }

                retEUR.m_bReturn       = true;
                retEUR.m_strImageURL   = EUInitOut.strWaveCodeURL;
                retEUR.m_strDirectURL  = EUInitOut.strDirectEnrolURL;
                retEUR.m_strNextURL    = EUInitOut.strValidateURL;
                retEUR.m_strStatusURL  = EUInitOut.strStatusURL;
                retEUR.m_strUserName   = strUserName;
            }
            return retEUR;
        }

        //Internal Enrol helper methods (EnrolUserInit, EnrolUserValidate, EnrolUserConfirm), use to be in ICipheriseServiceProvider.
        public async Task<EnrolUserReturn> EnrolUserValidate(EnrolUserReturn FromEnrolUserInit)
        {
            "EnrolUserValidate()".TraceVerbose();

            EnrolUserReturn retEUR = new EnrolUserReturn();

            if (    (string.IsNullOrEmpty(FromEnrolUserInit.m_strUserName))
                ||  (string.IsNullOrEmpty(FromEnrolUserInit.m_strNextURL))    )
                return retEUR;

            //Init session
            {
                CipheriseErrorImple CSError = new CipheriseErrorImple();
                if (await InitSession(true, CSError) == false)
                {
                    "Unable to initialise session.".TraceWarning();
                    retEUR.m_strCipheriseError = CSError.GetError();
                    return retEUR;
                }
            }

            //Enrol User/Device Status
            {
                int iPollTime = FromEnrolUserInit.m_iPollingTimeInMilliseconds;  //0 = Default value. -1 = indefinitely
                if (iPollTime == 0)
                    iPollTime = 3000; //Default.
                else if (iPollTime < -1)
                    iPollTime = -1;

                if ((iPollTime != -1) && (FromEnrolUserInit.CanContinuePolling != null))
                {
                    while (true)
                    {
                        if (FromEnrolUserInit.CanContinuePolling() == false)
                        {
                            "Enrol User Validate cancelled!".TraceVerbose();
                            return retEUR;
                        }

                        // Enrolment WaveCode status - Short poll.
                        EnrolWaveStatusOut OutStatus = await FromEnrolUserInit.m_strStatusURL.CipheriseRequest<EnrolWaveStatusOut>(m_strSessionID);
                        if (OutStatus == null) break;
                        if (OutStatus.HasError())
                        {
                            retEUR.m_strCipheriseError = OutStatus.GetError();
                            return retEUR;
                        }

                        string strStatusMessage = "Enrolment Status = " + OutStatus.strWaveStatus;
                        strStatusMessage.TraceVerbose();

                        //initialised / scanned / done / not found
                        if (OutStatus.strWaveStatus.CompareNoCase("not found"))
                        {
                            "Enrol User Wave status timed out!".TraceVerbose();
                            retEUR.m_bWaveTimeout = true;
                            return retEUR;
                        }

                        if (OutStatus.strWaveStatus.CompareNoCase("scanned") == false)  //initialised / scanned / done
                        {
                            await Task.Delay(iPollTime);
                            continue;
                        }
                        break;
                    }
                }

                //Enrol User/Device Validate
                EnrolUserValidateOut EUValidateOut = await FromEnrolUserInit.m_strNextURL.CipheriseRequest<EnrolUserValidateOut>(m_strSessionID);
                if (null == EUValidateOut)
                {
                    "Enrol User Validate failed!".TraceError();
                    return retEUR;
                }
                if (EUValidateOut.HasError())
                {
                    if (string.IsNullOrEmpty(retEUR.m_strCipheriseError))
                    {
                        if(EUValidateOut.ErrorContainsTimeout())
                            retEUR.m_bWaveTimeout = true;
                        else
                            retEUR.m_strCipheriseError = EUValidateOut.GetError();
                    }
                }
                if (retEUR.m_bWaveTimeout || (string.IsNullOrEmpty(retEUR.m_strCipheriseError) == false))
                    return retEUR;

                string strPubKeyForPayload = null;

                //Convert PubKeys to Signatures.
                for (int i = 1; i <= EUValidateOut.aPublicKeys.Count; ++i)
                {
                    string strNum = i.ToString();
                    string strPubKey = null;
                    if (false == EUValidateOut.aPublicKeys.TryGetValue(strNum, out strPubKey))
                    {
                        "Failed getting public key.".TraceVerbose();
                        return retEUR;
                    }

                    if (i == 1)
                        strPubKeyForPayload = strPubKey;  //For payload

                    string strSigned;
                    if (false == m_BC.GetCipheriseSignature(m_strCipheriseServer, m_strServiceProviderID, FromEnrolUserInit.m_strUserName, EUValidateOut.strDeviceID, strPubKey, i, out strSigned))
                    {
                        "Failed signing service signature.".TraceVerbose();
                        return retEUR;
                    }
                    EUValidateOut.aPublicKeys[strNum] =  strSigned;
                }

                retEUR.m_bReturn                    = true;
                retEUR.m_strImageURL                = EUValidateOut.strIdenticonURL;
                retEUR.m_strNextURL                 = EUValidateOut.strConfirmationURL;
                retEUR.m_strDeviceID                = EUValidateOut.strDeviceID;
                retEUR.m_aSignatures                = EUValidateOut.aPublicKeys;  //PubKeys are now Signatures.
                retEUR.m_strPublicKeyForPayload     = strPubKeyForPayload;
            }
            return retEUR;
        }  // EnrolUserValidate

        //Internal Enrol helper methods (EnrolUserInit, EnrolUserValidate, EnrolUserConfirm), use to be in ICipheriseServiceProvider.
        public async Task<EnrolUserReturn> EnrolUserConfirm(bool bConfirmed, EnrolUserReturn FromEnrolUserValidate)
        {
            return await EnrolUserConfirmEx(bConfirmed, FromEnrolUserValidate, null);
        }  // EnrolUserConfirm

        private async Task<EnrolUserReturn> EnrolUserConfirmEx(bool bConfirmed, EnrolUserReturn FromEnrolUserValidate, ICipherisePayload PayloadCB)
        {
            "EnrolUserConfirmEx()".TraceVerbose();

            if (bConfirmed && (PayloadCB != null))
                PayloadCB.PayloadToSend(ref FromEnrolUserValidate.m_kvpPayloadSet, ref FromEnrolUserValidate.m_astrPayloadGetKeys);

            EnrolUserReturn retEUR = new EnrolUserReturn();

            if (string.IsNullOrEmpty(FromEnrolUserValidate.m_strNextURL) || (FromEnrolUserValidate.m_aSignatures == null))
                return retEUR;

            //Init Session
            {
                CipheriseErrorImple CSError = new CipheriseErrorImple();
                if (await InitSession(true, CSError) == false)
                {
                    "Unable to initialise session.".TraceWarning();
                    retEUR.m_strCipheriseError = CSError.GetError();
                    return retEUR;
                }
            }

            //Enrol User/Device  Validate
            {
                //Create the BC with device public key. Used for payload request generation and payload response parsing.
                CipheriseBouncyCastle BCDevice = new CipheriseBouncyCastle();
                if (false == BCDevice.SetPEMPublicKey(FromEnrolUserValidate.m_strPublicKeyForPayload))
                {
                    "Unable to load device public key for generating payload.".TraceError();
                    return retEUR;
                }

                //Create Payload request.
                Payload payloadIn = null;
                if (bConfirmed)
                {
                    payloadIn = Payload.GeneratePayload(FromEnrolUserValidate.m_kvpPayloadSet, FromEnrolUserValidate.m_astrPayloadGetKeys, BCDevice, m_BC, out retEUR.m_strCipheriseError);
                    if ((payloadIn == null) && retEUR.m_strCipheriseError.IsValid())
                    {
                        "GeneratePayload failed!".TraceError();
                        return retEUR;
                    }
                }

                EnrolUserConfirmIn EUConfirmIn = new EnrolUserConfirmIn(bConfirmed, FromEnrolUserValidate.m_aSignatures, payloadIn);

                EnrolUserConfirmOut EUConfirmOut = await FromEnrolUserValidate.m_strNextURL.CipheriseRequest<EnrolUserConfirmOut>(EUConfirmIn.ToJSON(), m_strSessionID);
                if(EUConfirmOut == null)
                {
                    "Enrol User Confirm failed!".TraceError();
                    return retEUR;
                }
                if (EUConfirmOut.HasError())
                {
                    "Enrol User Confirm error!".TraceError();
                    retEUR.m_strCipheriseError = EUConfirmOut.GetError();

                    //if(EUConfirmOut.m_iError == 505) 
                    //{
                    //   Payload too big.
                    //   FUTURE: regenerate payload and resend.
                    //}

                    //Couldnt recover, so cancel the enrolment.
                    bConfirmed = false;
                    payloadIn  = null;

                    EnrolUserConfirmIn  EUConfirmInFail  = new EnrolUserConfirmIn(bConfirmed, FromEnrolUserValidate.m_aSignatures, payloadIn);
                    EnrolUserConfirmOut EUConfirmOutFail = await FromEnrolUserValidate.m_strNextURL.CipheriseRequest<EnrolUserConfirmOut>(EUConfirmInFail.ToJSON(), m_strSessionID);
                    if (EUConfirmOutFail == null)
                        "Enrol User Confirm (force fail) failed!".TraceError();
                    else if (EUConfirmOutFail.HasError())
                        EUConfirmOutFail.GetError().TraceError();

                    return retEUR;
                }

                bool bFinalConfirm = true;
                if (bConfirmed && (EUConfirmIn.payload != null))
                {
                    bFinalConfirm = false;

                    if (string.IsNullOrEmpty(EUConfirmOut.strPayloadVerifyURL))
                    {
                        "Enrol User Confirm failed: No Payload URL".TraceError();
                        return retEUR;
                    }

                    PayloadResponse payloadResponse = null;
                    try
                    {
                        if (EUConfirmOut.payload == null)
                        {
                            retEUR.m_strCipheriseError = "No Payload response!".TraceError(); //LOCALISE
                            return retEUR;
                        }

                        if (false == EUConfirmOut.payload.ParsePayloadResponse(out payloadResponse, BCDevice, m_BC))
                        {
                            if (retEUR.m_strCipheriseError.IsNotValid())
                            {
                                if (payloadResponse.HasError())
                                    retEUR.m_strCipheriseError = payloadResponse.GetError();
                                else
                                    retEUR.m_strCipheriseError = "Payload response failed to parse!".TraceError(); //LOCALISE
                            }
                            return retEUR;
                        }

                        if ((payloadResponse.bSet == false) && (FromEnrolUserValidate.m_kvpPayloadSet != null) && (FromEnrolUserValidate.m_kvpPayloadSet.Count > 0))
                        {
                            retEUR.m_strCipheriseError = "Payload response 'set' failed!".TraceError(); //LOCALISE
                            return retEUR;
                        }

                        bFinalConfirm = true;
                    }
                    finally
                    {
                        if (bFinalConfirm)
                        {
                            if (PayloadCB != null)
                            {
                                bFinalConfirm = PayloadCB.PayloadResponseFromApp(payloadResponse.aGet);

                                if (false == bFinalConfirm)
                                    retEUR.m_strCipheriseError = "Payload response was rejected by SDK caller."; //LOCALISE
                            }
                            else
                                retEUR.m_kvpPayloadSet = payloadResponse.aGet;  //The 'Get' response (KVP) is returned in the 'Set' member.
                        }

                        VerifyIn VerIn = new VerifyIn(bFinalConfirm);
                        CipheriseCommon.CipheriseError CSError = await EUConfirmOut.strPayloadVerifyURL.CipheriseRequest<CipheriseCommon.CipheriseError>(VerIn.ToJSON(), m_strSessionID);
                        if ((CSError != null) && CSError.HasError())
                        {
                            retEUR.m_strCipheriseError = CSError.GetError();
                            bFinalConfirm = false;
                        }
                    }
                }

                retEUR.m_bReturn = bFinalConfirm;
            }
            return retEUR;
        }  // EnrolUserConfirmEx

        //ICipheriseServiceProvider
        public async Task<bool> EnrolUser(ICipheriseEnrolUser EnrolUserCB)
        {
            "EnrolUser()".TraceVerbose();

            if (EnrolUserCB == null)
                return false;

            string strUserName = EnrolUserCB.GetUserName();
            if (string.IsNullOrEmpty(strUserName))
                return false;

            EnrolUserReturn EURValidate = null;
            bool bConfirmed = false;
            while(true)  //if WaveCode times out, generate a new one.
            {
                //Enrol User/Device  Init
                string strValidateURL;
                EnrolUserReturn EURInit = null;
                {
                    EURInit = await EnrolUserInit(strUserName);
                    if (EURInit.m_bReturn == false)
                        return false;

                    //Return WaveCode URL to caller
                    if (false == EnrolUserCB.DisplayWaveCode(EURInit.m_strImageURL))
                    {
                        "User cancelled Wave.".TraceVerbose();
                        EnrolUserCB.Enrolment(false, null, null);
                        return true;
                    }

                    if ((m_iSDKVersion >= CipheriseSP.SDK_VERSION_2) && (string.IsNullOrEmpty(EURInit.m_strDirectURL) == false))
                    {
                        //Return Direct Enrol URL to caller
                        if (false == EnrolUserCB.DisplayDirectURL(EURInit.m_strDirectURL))
                        {
                            "User cancelled Direct Enrol.".TraceVerbose();
                            EnrolUserCB.Enrolment(false, null, null);
                            return true;
                        }
                    }

                    strValidateURL = EURInit.m_strNextURL;
                }

                //Enrol User/Device  Validate
                EURValidate = null;
                bConfirmed = false;
                {
                    EURInit.m_iPollingTimeInMilliseconds = EnrolUserCB.GetPollTimeInMilliseconds();
                    EURInit.CanContinuePolling          = EnrolUserCB.CanContinuePolling;

                    EURValidate = await EnrolUserValidate(EURInit);
                    if (EURValidate.m_bReturn == false)
                    {
                        if (false == string.IsNullOrEmpty(EURValidate.m_strCipheriseError))
                        {
                            EnrolUserCB.CipheriseError(EURValidate.m_strCipheriseError);
                            return false;
                        }
                        if (EURValidate.m_bWaveTimeout == false)
                            return false;

                        //WaveCode time out, generate a new one.
                        if (EnrolUserCB.RepeatOnTimeout())
                            continue; //while (true);

                        return false;
                    }

                    //Return Identicon URL to caller
                    //Identicon is empty when direct enrolment is used. In this scenario, ignore the identicon and just set bConfirmed to true;
                    if ((false == string.IsNullOrEmpty(EURValidate.m_strImageURL)) && (false == EnrolUserCB.DisplayIdenticon(EURValidate.m_strImageURL)))
                    {
                        "User cancelled Identicon.".TraceVerbose();
                        //return false;  //Allow the 'confirm' to be be sent as 'reject'
                    }
                    else
                        bConfirmed = true;
                }

                break;
            } //while (true);

            //Enrol User/Device Confirm
            {
                EnrolUserReturn EURConfirm = await EnrolUserConfirmEx(bConfirmed, EURValidate, EnrolUserCB);
                if (EURConfirm.m_bReturn == false)
                {
                    if (EURConfirm.m_strCipheriseError.IsValid())
                        EnrolUserCB.CipheriseError(EURConfirm.m_strCipheriseError);

                    return false;
                }
            }

            EnrolUserCB.Enrolment(bConfirmed, strUserName, EURValidate.m_strDeviceID);
            return true;
        }

        private bool VerifySignatures(string strUserName, string strDeviceID, NumberDictionary mapPublicKeys, NumberDictionary mapSignatures)
        {
            if (   string.IsNullOrEmpty(strUserName)
                || string.IsNullOrEmpty(strDeviceID)
                || (mapPublicKeys == null)
                || (mapSignatures == null)
                || (mapPublicKeys.Count != mapSignatures.Count))
                return false;

            int iCount = mapPublicKeys.Count;
            for (int i = 1; i <= iCount; ++i)
            {
                string strNum  = i.ToString();

                string strPubKey = null;
                if ((false == mapPublicKeys.TryGetValue(strNum, out strPubKey)) || string.IsNullOrEmpty(strPubKey))
                    return false;

                string strSig = null;
                if ((false == mapSignatures.TryGetValue(strNum, out strSig)) || string.IsNullOrEmpty(strSig))
                    return false;

                if (false == m_BC.VerifyCipheriseSignature(m_strCipheriseServer, m_strServiceProviderID, strUserName, strDeviceID, strPubKey, i, strSig))
                    return false;
            }

            return true;
        }

        //ICipheriseServiceProvider
        public async Task<bool> RetrieveUsersDevices(ICipheriseDevice DeviceCB)
        {
            "RetrieveUsersDevices()".TraceVerbose();

            if (DeviceCB == null)
                return false;

            string strUserName = DeviceCB.GetUserName();
            if (string.IsNullOrEmpty(strUserName))
                return false;

            if (await InitSession(true, DeviceCB) == false)
            {
                "Unable to initialise session.".TraceWarning();
                return false;
            }

            string strURL = m_strCipheriseServer + "/sp/user-devices/" + Uri.EscapeDataString(strUserName);

            if (DeviceCB.IncludeUnauthorisedDevices())
                strURL += "?all=true";

            // Retrieve Users Devices
            DevicesOut aDevicesOut = await strURL.CipheriseRequest<DevicesOut>(m_strSessionID);
            if (null == aDevicesOut)
            {
                "User device retrieval failed!".TraceError();
                return false;
            }
            if (aDevicesOut.HasError())
            {
                DeviceCB.CipheriseError(aDevicesOut.GetError());
                return false;
            }

            bool bRet = aDevicesOut.aDevices.Count == 0;
            foreach (DeviceOut D in aDevicesOut.aDevices)
            {
                if (false == VerifySignatures(strUserName, D.strDeviceID, D.aPublicKeys, D.aSignatures))
                {
                    D.strFriendlyName.TraceWarning("Invalid device signature for: ");
                    continue;
                }

                bRet = true;
                if (false == DeviceCB.DeviceInfo(D.strFriendlyName, D.strDeviceID, (D.iBindingAuthorised !=0) && (D.iDeviceAuthorised !=0)))
                    break;
            }
            return bRet;
        }

        //ICipheriseServiceProvider
        public async Task<bool> RevokeUser(ICipheriseRevokeUser RevokeUserCB)
        {
            "RevokeUser()".TraceVerbose();

            if (RevokeUserCB == null)
                return false;

            string strUserName = RevokeUserCB.GetUserName();
            if (string.IsNullOrEmpty(strUserName))
                return false;

            string[] astrUDeviesIDs = RevokeUserCB.GetDeviceIDs();

            if (await InitSession(true, RevokeUserCB) == false)
            {
                "Unable to initialise session.".TraceWarning();
                return false;
            }

            string strURL = m_strCipheriseServer + "/sp/revoke-user/";

            RevokeUserIn revokeUser = new RevokeUserIn(strUserName, astrUDeviesIDs);

            // Revoke User
            RevokeUserOut aOut = await strURL.CipheriseRequest<RevokeUserOut>(revokeUser.ToJSON(), m_strSessionID);
            if (null == aOut)
            {
                "User revoke retrieval failed!".TraceError();
                return false;
            }
            if (aOut.HasError())
            {
                RevokeUserCB.CipheriseError(aOut.GetError());
                return false;
            }

            if ((aOut.astrInvalidDeviceIDs != null) && aOut.astrInvalidDeviceIDs.Length > 0)
                RevokeUserCB.SetInvalidIDs(aOut.astrInvalidDeviceIDs);

            return true;
        }

        private bool GetDevicePublicKeyFromPEM(string strPublicKey, out AsymmetricKeyParameter rsaDevicePubKey)
        {
            rsaDevicePubKey = null;
            AsymmetricKeyParameter AKPOut = null;

            if (strPublicKey == null)
                "No matching device public key for device ID".TraceError();
            else if (false == strPublicKey.FromPem(out AKPOut))
                "Invalid device public key".TraceError();
            else if (AKPOut == null)
                "Invalid device public key object".TraceError();
            else if (AKPOut.IsPrivate)
                "Device Key is not public!".TraceError();
            else
                rsaDevicePubKey = AKPOut;
            return rsaDevicePubKey != null;
        }


        private delegate bool PostAuthCallback(AuthenticateOut Out);

        public async Task<bool> Authenticate(ICipheriseAuthenticate AuthCB)
        {
            try
            {
                return await AuthenticateEx(AuthCB);
            }
            catch (Exception e) { e.CatchMessage().TraceError(); }
            return false;
        }

        //ICipheriseServiceProvider V3
        public async Task<bool> AuthenticateEx(ICipheriseAuthenticate AuthCB)
        {
            "Authenticate()".TraceVerbose();

            if (AuthCB == null)
                return false;

            //Challenge for the APP to sign.
            byte[] aSPChallenge = new byte[32];
            aSPChallenge.FillRandom();
            string strSPChallenge = aSPChallenge.ToHexString();

            bool bWave = false;  //Implied by the type of AuthCB
            PostAuthCallback PostAuthCB = null;
            AuthenticateIn In = null;

            if (AuthCB is ICipheriseAuthenticatePush)
            {
                ICipheriseAuthenticatePush AuthPush = (AuthCB as ICipheriseAuthenticatePush);

                bool bValidUserName = false;
                In = AuthenticateIn.CreateAuthenticatePush(AuthPush, out bValidUserName);

                if ((In == null) && bValidUserName)
                    return false;
            }

            if ((In == null) && (AuthCB is ICipheriseAuthenticateWave))
            {
                bWave = true;
                In = AuthenticateIn.CreateAuthenticateWave();

                PostAuthCB = new PostAuthCallback((AuthenticateOut Out) =>
                {
                    ICipheriseAuthenticateWave WaveAuth = (AuthCB as ICipheriseAuthenticateWave);

                    //Return WaveCode URL to caller
                    if (false == WaveAuth.DisplayWaveCode(Out.strWaveCodeURL))
                   {
                       "User cancelled WAVE.".TraceVerbose();
                       return false;
                   }
                   
                   if ((m_iSDKVersion >= CipheriseSP.SDK_VERSION_2) && (string.IsNullOrEmpty(Out.strDirectURL) == false))
                   {
                       //Return Direct Auth URL to caller
                       if (false == WaveAuth.DisplayDirectURL(Out.strDirectURL))
                       {
                           "User cancelled Direct Auth.".TraceVerbose();
                           return false;
                       }
                   }
                   return true;
                });
            }

            if (In == null)
                return false;

            if (false == await InitSession(true, AuthCB))
            {
                "Unable to initialise session.".TraceWarning();
                return false;
            }

            while (true)
            {
                AuthenticateOut Out = await (m_strCipheriseServer + "/sp/authentication").CipheriseRequest<AuthenticateOut>(In.ToJSON(), m_strSessionID, (ref AuthenticateOut Out1) => Out1.Update(bWave) );
                if (null == Out)
                {
                    "Authenticate request failed!".TraceError();
                    return false;
                }
                if (Out.HasError())
                {
                    AuthCB.CipheriseError(Out.GetError());
                    return false;
                }

                if (PostAuthCB != null)
                {
                    if (false == PostAuthCB(Out))
                    {
                        AuthCB.Authenticated(CipheriseAuthenticationResponse.eCAR_Cancel, null, null, null);
                        return true;
                    }
                }

                //Short Poll the CS for status of auth. Wait for App = FALSE
                AuthReturn S = await AuthenticateStatus(Out.strStatusURL, Out.strGetAppChallengeURL, Out.strChallengeExchangeURL, strSPChallenge, AuthCB);
                if (S == AuthReturn.Failure)
                    return false;

                if (S == AuthReturn.Timeout)
                {
                    if (AuthCB.RepeatOnTimeout())
                        continue;  //Repeat

                    //Dont repeat.
                    AuthCB.Authenticated(CipheriseAuthenticationResponse.eCAR_Cancel, null, null, null);
                    return true;
                }

                if (S == AuthReturn.Cancelled)
                {
                    AuthCB.Authenticated(CipheriseAuthenticationResponse.eCAR_Cancel, null, null, null);
                    return true;
                }

                //Long poll.
                return await AuthenticateAppSolutionAndVerify(Out.strChallengeExchangeURL, strSPChallenge, AuthCB);

            } //while(true)
        } //Authenticate

        public async Task<bool> AuthenticateAppSolutionAndVerify(string strChallengeExchangeURL, string strSPChallenge, ICipheriseAuthenticate AuthCB)
        {
            AuthenticateAppSolutionOut Out = await strChallengeExchangeURL.CipheriseRequest<AuthenticateAppSolutionOut>(m_strSessionID);
            if (null == Out)
            {
                "AuthenticateAppSolutionAndVerify request failed!".TraceError();
                return false;
            }
            if (Out.HasError())
            {
                AuthCB.CipheriseError(Out.GetError());
                return false;
            }

            //Variables required for "finally"
            CipheriseAuthenticationResponse eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
            string strVerifyFailMessage = null; //Sent to the SDK caller and the App. Must be localised.
            bool bRet = false;
            try
            {
                //Response
                     if (Out.strAuthenticated.CompareNoCase("true"))      eAuthResponse = CipheriseAuthenticationResponse.eCAR_Accept;
                else if (Out.strAuthenticated.CompareNoCase("false"))     eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
                else if (Out.strAuthenticated.CompareNoCase("cancelled")) eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
                else if (Out.strAuthenticated.CompareNoCase("report"))    eAuthResponse = CipheriseAuthenticationResponse.eCAR_Report;
                else if (Out.strAuthenticated.CompareNoCase("reported"))  eAuthResponse = CipheriseAuthenticationResponse.eCAR_Report;
                else
                {
                    strVerifyFailMessage = "Invalid authentication response: {0}".FS(Out.strAuthenticated);  //LOCALISE
                    return false;
                }
                if (eAuthResponse != CipheriseAuthenticationResponse.eCAR_Accept)
                {
                    "Auth: authentication response: {0}".FS(Out.strAuthenticated).TraceVerbose();
                    return true;
                }

                //Verify
                AsymmetricKeyParameter rsaDevicePubKey = null;
                strVerifyFailMessage = VerifyAuthChallengeAndSignature(ref rsaDevicePubKey, Out.strPublicKey, strSPChallenge, Out.strSolution,
                                                                       Out.strUserName, Out.strDeviceID, Out.iPubKeyLevel, Out.strKeySignature);

                if (strVerifyFailMessage != null)
                {
                    eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
                    return false;
                }

                //Payload
                {
                    KeyValuePairs akvpPayloadSet = null;
                    string[] aKeysPayloadGet = null;

                    AuthCB.PayloadToSend(ref akvpPayloadSet, ref aKeysPayloadGet);
                    bool bPayload = (   ((akvpPayloadSet  != null) && (akvpPayloadSet.Count   > 0))
                                     || ((aKeysPayloadGet != null) && (aKeysPayloadGet.Length > 0)));

                    if (bPayload)
                    {
                        strVerifyFailMessage = await GenerateAndSendPayload(Out.strPayloadURL, akvpPayloadSet, aKeysPayloadGet, rsaDevicePubKey, AuthCB);
                        if (strVerifyFailMessage != null)
                        {
                            eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
                            return false;
                        }
                    }
                }
            }
            finally
            {
                //strVerifyFailMessage:  Sent to the SDK caller and the App. Must be localised.
                bRet = await VerifyFinalAuth(eAuthResponse, strVerifyFailMessage, "Auth: ", Out.strVerifyAuthURL, AuthCB, Out.strUserName, Out.strDeviceName, Out.strDeviceID);
            }

            return bRet;
        } // AuthenticateAppSolutionAndVerify

        private enum AuthReturn { Failure, Success, Timeout, Cancelled };
        private delegate Task<AuthReturn> ExchangeDelegate();

        private async Task<AuthReturn> AuthenticateStatus(string strStatusURL, string strGetAppChallengeURL, string strChallengeExchangeURL, string strSPChallenge, ICipheriseAuthenticate AuthCB)
        {
            //Short Poll the CS for status of auth

            int iPollTime = AuthCB.GetPollTimeInMilliseconds();  //0 = Default value. -1 = indefinitely (long poll)
            if (iPollTime == 0)
                iPollTime = 3000; //Default.
            else if (iPollTime <= -1)
            {
                //Long poll.
                return await AuthenticateAppChallenge(strGetAppChallengeURL, strChallengeExchangeURL, strSPChallenge, AuthCB, true);
           }

            bool bWaitingForCipheriseAppCalled = false;

            while (true)
            {
                // Auth Status - Short poll.
                AuthenticateStatusOut OutStatus = await strStatusURL.CipheriseRequest<AuthenticateStatusOut>(m_strSessionID);
                if (OutStatus == null)
                {
                    "AuthenticateStatus failed!".TraceError();
                    return AuthReturn.Failure;
                }

                if (OutStatus.HasError())
                {
                    AuthCB.CipheriseError(OutStatus.GetError());
                    return AuthReturn.Failure;
                }

                string strStatusMessage = "AuthenticationStatus = " + OutStatus.strStatusText + " " + OutStatus.iStatusCode;
                strStatusMessage.TraceVerbose();

                const int StatusCodeInit       = 40100;           //StatusCodeInit indicated initialise stage of authentication
                //const int StatusCodeScanned    = 40200;           //StatusCodeScanned indicated auth entering into attempt stage
                const int StatusCodePendingSP  = 40300;           //StatusCodePendingSP indicated auth enterinng into pending sp solution stage
                //const int StatusCodePendingApp = 40400;           //StatusCodePendingApp indicated auth enterinng into pending authentication solution stage
                const int StatusCodeDone       = 40500;           //StatusCodeDone indicated auth entering to the final stage
                const int StatusCodeNotFound   = 40600;           //StatusCodeNotFound indicated auth not found

                if (StatusCodeInit != OutStatus.iStatusCode)
                {
                    if (false == bWaitingForCipheriseAppCalled)
                    {
                        bWaitingForCipheriseAppCalled = true;
                        AuthCB.WaitingForCipheriseApp();
                    }
                }

                //Not Found
                if(StatusCodeNotFound == OutStatus.iStatusCode)
                {
                    "Authentication status timed out!".TraceVerbose();
                    return AuthReturn.Timeout;  //Timeout: Caller can repeat Auth flow again
                }

                //Done
                if (StatusCodeDone == OutStatus.iStatusCode)
                {
                    return AuthReturn.Success;  //Continue Auth flow
                }

                //SP Solution required - Bidirectional only.
                if (StatusCodePendingSP == OutStatus.iStatusCode)
                {
                    AuthReturn T = await AuthenticateAppChallenge(strGetAppChallengeURL, strChallengeExchangeURL, strSPChallenge, AuthCB, false);
                    if (T != AuthReturn.Success)
                        return T;
                }

                // Its the callers responsibility to cancel this loop, if required.
                if (AuthCB.CanContinuePolling() == false)
                {
                    return AuthReturn.Cancelled;
                }

                await Task.Delay(iPollTime);
            } //while
        } // AuthenticateStatus

        private async Task<AuthReturn> AuthenticateAppChallenge(string strGetAppChallengeURL, string strChallengeExchangeURL, string strSPChallenge, ICipheriseAuthenticate AuthCB, bool bCallWaitingForCipheriseApp)
        {
            AuthenticateExchangeIn In = new AuthenticateExchangeIn();

            {
                AuthenticateAppChallengeOut OutChallenge = await strGetAppChallengeURL.CipheriseRequest<AuthenticateAppChallengeOut>(m_strSessionID);

                if (bCallWaitingForCipheriseApp)
                    AuthCB.WaitingForCipheriseApp();

                if (OutChallenge == null)
                {
                    "AuthenticateAppChallenge failed!".TraceError();
                    return AuthReturn.Failure;
                }

                if (OutChallenge.HasError())
                {
                    if (OutChallenge.ErrorContainsTimeout())
                        return AuthReturn.Timeout;

                    AuthCB.CipheriseError(OutChallenge.GetError());
                    return AuthReturn.Failure;
                }

                //OutChallenge.strAppChallenge.TraceDebug("App Challenge: ");
                //OutChallenge.strUsername.TraceDebug("User name: ");

                string strAppSolution = null;
                if (false == m_BC.SignHexString(OutChallenge.strAppChallenge, out strAppSolution))
                    In.SetError(800);
                else
                {
                    In.SetAppSolution(strAppSolution);
                    In.SetSPChallenge(strSPChallenge);

                    //Notify the SP when the Cipherise App has determined the username.
                    if (OutChallenge.strUsername.IsStringValid())
                        AuthCB.CipheriseAppDetails(OutChallenge.strUsername);

                    In.SetAuthDetails(AuthCB);
                    In.bWaitForAppSolution = false;  //Returns immediately. Get SP solution in next status StatusCodePendingApp
                }
            }

            ExchangeDelegate Exchange = async () =>
            {
                CipheriseCommon.CipheriseError OutError = await strChallengeExchangeURL.CipheriseRequest<CipheriseCommon.CipheriseError>(In.ToJSON(), m_strSessionID);
                if (OutError == null)
                {
                    "AuthenticateAppChallenge Exchange failed!".TraceError();
                    return AuthReturn.Failure;
                }

                if (OutError.HasError())
                {
                    AuthCB.CipheriseError(OutError.GetError());
                    return AuthReturn.Failure;
                }
                return AuthReturn.Success; ;
            };

            AuthReturn E = await Exchange();
            if ((AuthReturn.Failure == E) && (false == In.IsError()))
            {
                In.SetError(800);
                await Exchange();
            }
            return E;
        } // AuthenticateAppChallenge

        //The returned string is sent to the SDK caller and the App. Must be localised.
        private string VerifyAuthChallengeAndSignature(ref AsymmetricKeyParameter rsaDevicePubKey, string strPublicKeyPEM, string strAuthChallenge, string strAuthSolution,
                                                        string strUserName, string strDeviceID, int iDevicePKLevel, string strSignature)
        {
            //Verify AuthChallenge.
            {
                //Get the users/devices public key
                if (false == GetDevicePublicKeyFromPEM(strPublicKeyPEM, out rsaDevicePubKey))
                    return "Unable to get PEM from the devices public key.";  //LOCALISE

                if (false == rsaDevicePubKey.VerifyHexString(strAuthChallenge, strAuthSolution))
                    return "Invalid authentication solution!"; //LOCALISE
            }

            //Verify Service Signature
            {
                if (m_BC.VerifyCipheriseSignature(m_strCipheriseServer, m_strServiceProviderID, strUserName, strDeviceID, strPublicKeyPEM, iDevicePKLevel, strSignature) == false)
                    return "Invalid device signature!"; //LOCALISE
            }

            return null;
        } // VerifyAuthChallengeAndSignature

        //The returned string is sent to the SDK caller and the App. Must be localised.
        private async Task<string> GenerateAndSendPayload(string strPayloadURL, KeyValuePairs akvpPayloadSet, string[] aKeysPayloadGet, AsymmetricKeyParameter rsaDevicePubKey, ICipheriseAuthenticate AuthCB)
        {
            if (string.IsNullOrEmpty(strPayloadURL))
                return null;  //Do not return an error string.

            //Create the BC with device public key. Used for payload request generation and payload response parsing.
            CipheriseBouncyCastle BCDevice = new CipheriseBouncyCastle();
            BCDevice.SetPublicKey(rsaDevicePubKey);

            //Create Payload request.
            string strPayloadError = null;
            Payload payloadIn = Payload.GeneratePayload(akvpPayloadSet, aKeysPayloadGet, BCDevice, m_BC, out strPayloadError);
            if (payloadIn == null)
                return strPayloadError ?? "Unable to generate payload."; //LOCALISE

            return await SendPayload(payloadIn, strPayloadURL, AuthCB, BCDevice, m_BC);
        } // GenerateAndSendPayload

        //The returned string is sent to the SDK caller and the App. Must be localised.
        private async Task<string> SendPayload(Payload payloadIn, string strPayloadURL, ICipherisePayload PayloadCB, CipheriseBouncyCastle BCDevice, CipheriseBouncyCastle BCServiceProvider)
        {
            PayloadInOut In = new PayloadInOut(payloadIn);

            PayloadInOut Out = await strPayloadURL.CipheriseRequest<PayloadInOut>(In.ToJSON(), m_strSessionID);
            if (null == Out)
                return "Sending Payload failed!";  //LOCALISE
            if (Out.HasError())
                return Out.GetError();

            PayloadResponse R = null;
            if (false == Out.payload.ParsePayloadResponse(out R, BCDevice, BCServiceProvider))
            {
                if ((R != null) && R.HasError())
                    return R.GetError();

                return "Parsing payload response failed!"; //LOCALISE
            }

            if (PayloadCB != null)
            {
                if (false == PayloadCB.PayloadResponseFromApp(R.aGet))
                    return "Payload response was rejected by SDK caller."; //LOCALISE
            }

            return null;
        } // SendPayload

        private async Task<bool> VerifyFinalAuth(CipheriseAuthenticationResponse eAuthResponse, string strVerifyFailMessage, string strPreFailMessage, string strVerifyAuthURL, ICipheriseAuthenticate AuthCB, string strUserName, string strDeviceName, string strDeviceID)
        {
            //strVerifyFailMessage:  Sent to the SDK caller and the App. Must be localised.

            if (strVerifyFailMessage.IsValid())
            {
                (strPreFailMessage + strVerifyFailMessage).TraceError();
                if (eAuthResponse == CipheriseAuthenticationResponse.eCAR_Accept)
                    eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;

                AuthCB.CipheriseError(strVerifyFailMessage);
            }

            bool bVerify = false;
            if (strVerifyAuthURL.IsValid())
            {
                bVerify = await AuthVerify((eAuthResponse == CipheriseAuthenticationResponse.eCAR_Accept), strVerifyAuthURL, strVerifyFailMessage, AuthCB, strPreFailMessage);
                if (false == bVerify)
                {
                    "AuthVerify failed!".TraceError();
                    eAuthResponse = CipheriseAuthenticationResponse.eCAR_Cancel;
                }
            }
            AuthCB.Authenticated(eAuthResponse, strUserName, strDeviceName, strDeviceID);
            return bVerify;
        } // VerifyFinalAuth

        private async Task<bool> AuthVerify(bool bVerified, string strVerifyAuthURL, string strFailReason, ICipheriseError CError, string strPreFailMessage)
        {
            VerifyIn In = new VerifyIn(bVerified, strFailReason);

            CipheriseCommon.EmptyResponse Out = await strVerifyAuthURL.CipheriseRequest<CipheriseCommon.EmptyResponse>(In.ToJSON(), m_strSessionID);
            if (null == Out)
            {
                if(CError != null)
                    CError.CipheriseError(strPreFailMessage + "Auth verify failed!");
                return false;
            }

            if (Out.HasError())
            {
                if (CError != null)
                    CError.CipheriseError(Out.GetError());
                return false;
            }

            return true;
        } // AuthVerify

        //Pass in a previous session.
        public bool SetPreviousSessionID(string strSessionID)
        {
            if (m_strSessionID.IsValid())
                return false;

            m_strServiceProviderID.TraceVerbose("InitSession() SPID: ");

            if (string.IsNullOrEmpty(m_strServiceProviderID))
                return false;

            if (LoadKeyFromFile() == false)
                return false;

             m_strSessionID = strSessionID;
            return true;
        }

        //ICipheriseError implementation to use when caller doesnt provide one.
        private class CipheriseErrorImple : ICipheriseError
        {
            private string m_strError;

            public void CipheriseError(string strError)
            {
                m_strError = strError;
            }

            public string GetError()
            {
                return m_strError;
            }
        }

        private async Task<bool> InitSession(bool bKeepOpen, ICipheriseError CError)
        {
            if (m_strSessionID.IsValid())
                return true;

            m_strServiceProviderID.TraceVerbose("InitSession() SPID: ");

            if (string.IsNullOrEmpty(m_strServiceProviderID))
                return false;

            if (LoadKeyFromFile() == false)
                return false;

            string strSessionID = await StartSession(CError);
            if (null == strSessionID)
            {
                "Unable to start session.".TraceWarning();
                return false;
            }

            if (bKeepOpen)
                m_strSessionID = strSessionID;
            return true;
        }

        private bool GetKeyFilename(bool bShouldExist, out string strKeyFilename)
        {
            strKeyFilename = null;
            try
            {
                string strFilename;
                if (string.IsNullOrEmpty(m_strKeyLocation))
                    strFilename = m_strServiceProviderID + ".key";
                else
                    strFilename = m_strKeyLocation + "\\" + m_strServiceProviderID + ".key";

                if (File.Exists(strFilename) != bShouldExist)
                    return false;

                strKeyFilename = strFilename;
                return true;
            }
            catch (Exception e) { e.CatchMessage().TraceError(); }
            return false;
        }

        private bool SaveKeyToFile()
        {
            string strFilename;
            if (GetKeyFilename(false, out strFilename) == false)
            {
                "Error with key file.".TraceError();
                return false;
            }

            return m_BC.SaveToFile(strFilename);
        }

        private bool LoadKeyFromFile()
        {
            string strFilename;
            if (GetKeyFilename(true, out strFilename) == false)
                return false;

            return m_BC.LoadFromFile(strFilename);
        }

        private async Task<string> StartSession(ICipheriseError E)
        {
            if(E == null)
            {
                Debug.Assert(E != null, "StartSession() has no ICipheriseError to use.");
                "StartSession() Internal error".TraceWarning();
                return null;
            }

            //SP Auth Init
            string strURL = m_strCipheriseServer + "/sp/authenticate-service/" + this.m_strServiceProviderID;
            SPAuthInitOut authInitOut = await strURL.CipheriseRequest<SPAuthInitOut>();
            if (null == authInitOut)
            {
                "SPAuthInitOut failed.".TraceWarning();
                return null;
            }

            if (authInitOut.HasError())
            {
                E.CipheriseError(authInitOut.GetError());
                return null;
            }

            string strSigned;
            if (m_BC.SignHexString(authInitOut.strAuthChallenge, out strSigned) == false)
            {
                "SignHexString failed.".TraceWarning();
                return null;
            }

            SPAuthValidateIn authValidIn  = new SPAuthValidateIn();
            authValidIn.strAuthToken      = authInitOut.strAuthToken;
            authValidIn.strAuthSolution   = strSigned;

            if (authValidIn.Validate() == false)
            {
                "Validate failed.".TraceWarning();
                return null;
            }

            //SP Auth Validate
            SPAuthValidateOut authValidOut = await (m_strCipheriseServer + "/sp/authenticate-service/").CipheriseRequest<SPAuthValidateOut>(authValidIn.ToJSON(), null, null);
            if (null == authValidOut)
            {
                "SPAuthValidateOut failed.".TraceWarning();
                return null;
            }

            if (authValidOut.HasError())
            {
                E.CipheriseError(authValidOut.GetError());
                return null;
            }

            return authValidOut.strSessionID;
        }

        //JSON for SP Auth Init (OUT)
        [DataContract]
        private class SPAuthInitOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "authToken")]
            public string strAuthToken { get; set; }

            [DataMember(Name = "spAuthChallenge")]
            public string strAuthChallenge { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && strAuthToken.IsValid()
                    && strAuthChallenge.IsValid();
            }
        } // SPAuthInitOut

        //JSON for SP Auth Validate (IN)
        [DataContract]
        private class SPAuthValidateIn : CipheriseCommon.IValidate
        {
            [DataMember(Name = "authToken")]
            public string strAuthToken { get; set; }

            [DataMember(Name = "spAuthChallengeSolution")]
            public string strAuthSolution { get; set; }

            public bool Validate()
            {
                return strAuthToken.IsValid()
                    && strAuthSolution.IsValid();
            }
        } // SPAuthValidateIn

        //JSON for SP Auth Validate (OUT)
        [DataContract]
        private class SPAuthValidateOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "sessionId")]
            public string strSessionID { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && strSessionID.IsValid();
            }
        } // SPAuthValidateOut

        //JSON for SP Register (IN)
        [DataContract]
        private class SPRegisterIn : CipheriseCommon.IValidate
        {
            [DataMember(Name = "friendlyName")]
            public string strFriendlyName { get; set; }

            [DataMember(Name = "publicKey")]
            public string strPublicKey { get; set; }

            public bool Validate()
            {
                return strFriendlyName.IsValid()
                    && strPublicKey.IsValid();
            }
        } // SPRegisterIn

        //JSON for Info (OUT)
        [DataContract]
        private class SPInfoOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "serverVersion")]
            public string strServerVersion { get; set; } = null;

            public override bool Validate()
            {
                return base.Validate()
                    && strServerVersion.IsValid()
                    && (strServerVersion.CompareNoCase("null") == false);
            }
        } // SPInfoOut

        //JSON for SP Register (OUT)
        [DataContract]
        private class SPRegisterOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "serviceId")]
            public string strServiceID { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && strServiceID.IsValid();
            }
        } // SPRegisterOut

        //JSON for SP EnrolUser init (IN)
        [DataContract]
        private class EnrolUserInitIn : CipheriseCommon.IValidate
        {
            [DataMember(Name = "username")]
            public string strUserName { get; set; }

            public bool Validate()
            {
                return strUserName.IsValid();
            }
        } // EnrolUserInitIn

        //JSON for SP EnrolUser init (OUT)
        [DataContract]
        private class EnrolUserInitOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "qrCodeURL")]
            public string strWaveCodeURL { get; set; }

            [DataMember(Name = "validateURL")]
            public string strValidateURL { get; set; }

            [DataMember(Name = "statusURL")]
            public string strStatusURL { get; set; }

            [DataMember(Name = "directEnrolURL")]
            public string strDirectEnrolURL { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && strWaveCodeURL.IsValid()
                    && strValidateURL.IsValid()
                    && strStatusURL.IsValid();
            }
        } // EnrolUserInitOut

        //JSON for SP Auth Wave status (OUT)
        [DataContract]
        private class EnrolWaveStatusOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "QREnrolStatus")]
            public string strWaveStatus { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && strWaveStatus.IsValid();
            }
        } // EnrolWaveStatusOut

        //JSON for SP EnrolUser Validate (OUT)
        [DataContract]
        private class EnrolUserValidateOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "identiconURL")]
            public string strIdenticonURL { get; set; }         //Empty when direct enrolment (directEnrolURL) is used. SP will skip the identicon flow.

            [DataMember(Name = "confirmationURL")]
            public string strConfirmationURL { get; set; }

            [DataMember(Name = "deviceId")]
            public string strDeviceID { get; set; }

            [DataMember(Name = "publicKeys")]
            public NumberDictionary aPublicKeys { get; set; }

            public override bool Validate()
            {
                if (base.Validate() == false)
                    return false;

                //  If there is an app error code, then this is valid (as an error) despite the the other fields being empty            
                if (m_iAppErrorCode != 0)
                    return true;

                return strConfirmationURL.IsValid()
                    //&& strIdenticonURL.IsValid()
                    && strDeviceID.IsValid()
                    && aPublicKeys.IsValidWithCount(4);
            }
        } // EnrolUserValidateOut

        //JSON for SP EnrolUser Confirm (IN)
        [DataContract]
        private class EnrolUserConfirmIn : CipheriseCommon.IValidate
        {
            public EnrolUserConfirmIn(bool bConfirmed, NumberDictionary aSignatures, Payload payloadIn)
            {
                strConfirm = bConfirmed ? "confirm" : "reject";
                mapSignatures = aSignatures;

                if (bConfirmed)
                    payload = payloadIn;
            }

            [DataMember(Name = "confirm")]
            public string strConfirm { get; set; }

            [DataMember(Name = "signatures")]
            public NumberDictionary mapSignatures { get; set; }

            [DataMember(Name = "payload", IsRequired = false, EmitDefaultValue = false)]
            public Payload payload { get; set; }

            public bool Validate()
            {
                return strConfirm.IsValid()
                    && mapSignatures.IsValidWithCount(4);
            }
        } // EnrolUserConfirmIn

        //JSON for SP EnrolUser Confirm (OUT)
        [DataContract]
        private class EnrolUserConfirmOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "confirm")]
            public string strConfirm { get; set; }

            [DataMember(Name = "payloadVerifyURL", IsRequired = false, EmitDefaultValue = false)]
            public string strPayloadVerifyURL { get; set; }

            [DataMember(Name = "payload", IsRequired = false, EmitDefaultValue = false)]
            public Payload payload { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && strConfirm.IsValid();
            }
        } // EnrolUserConfirmOut

        //JSON for SP Device retrieval (OUT)
        [DataContract]
        private class DeviceOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "deviceId")]
            public string strDeviceID { get; set; }

            [DataMember(Name = "friendlyName")]
            public string strFriendlyName { get; set; }

            [DataMember(Name = "publicKeys")]
            public NumberDictionary aPublicKeys { get; set; }

            [DataMember(Name = "signatures")]
            public NumberDictionary aSignatures { get; set; }

            [DataMember(Name = "bindingAuthorised")]
            public int iBindingAuthorised { get; set; }

            [DataMember(Name = "deviceAuthorised")]
            public int iDeviceAuthorised { get; set; }

            public override bool Validate()
            {
                if (HasError())
                    return false;

                return strDeviceID.IsValid()
                    && strFriendlyName.IsValid()
                    && aPublicKeys.IsValidWithCount(4)
                    && aSignatures.IsValidWithCount(4);
            }

            public bool IsAuthorised()
            {
                return ((iBindingAuthorised != 0) && (iDeviceAuthorised != 0));
            }
        } // DeviceOut

        //JSON for SP Device retrieval (OUT)
        [DataContract]
        private class DevicesOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "devices")]
            public List<DeviceOut> aDevices { get; set; }

            public override bool Validate()
            {
                if (base.Validate() == false)
                    return false;

                int iIndex = 0;
                foreach (DeviceOut D in aDevices)
                {
                    if (D.Validate() == false)
                    {
                        String.Format("Invalid List<DeviceOut> (index {0})", iIndex).TraceError();
                        return false;
                    }
                    ++iIndex;
                }
                return true; // iIndex > 0;
            }
        } // DevicesOut

        //JSON for SP Authentication Base (IN)
        [DataContract]
        private class AuthenticateBaseIn : CipheriseCommon.IValidate
        {
            public void SetAuthDetails(ICipheriseAuthenticate AuthCB)
            {
                iAuthLevel                = (int)AuthCB.GetAuthenticationType();
                strAuthenticationMessage  = AuthCB.GetAuthenticationMessage();
                strBrandingMessage        = AuthCB.GetBrandingMessage();

                if(AuthCB is ICipheriseAuthenticateWave)
                    strAppRedirectURL = (AuthCB as ICipheriseAuthenticateWave).GetRedirectURL();
            }

            public void SetPushNotificationMessage(ICipheriseAuthenticatePush AuthCB)
            {
                strNotificationMessage = AuthCB.GetNotificationMessage();
            }

            public void SetSPChallenge(string strSPChallenge)
            {
                strAuthChallenge = strSPChallenge;
            }

            protected virtual void Clear()
            {
                strAuthChallenge         = default(string);
                iAuthLevel               = default(int);
                strNotificationMessage   = default(string);
                strAuthenticationMessage = default(string);
                strBrandingMessage       = default(string);
                strAppRedirectURL        = default(string);
            }

            [DataMember(Name = "authenticationChallenge", IsRequired = false, EmitDefaultValue = false)]
            private string strAuthChallenge { get; set; } = default(string);

            [DataMember(Name = "authenticationLevel", IsRequired = false, EmitDefaultValue = false)]
            private int iAuthLevel { get; set; } = default(int);

            [DataMember(Name = "notificationMessage", IsRequired = false, EmitDefaultValue = false)]
            private string strNotificationMessage { get; set; } = default(string);

            [DataMember(Name = "authenticationMessage", IsRequired = false, EmitDefaultValue = false)]
            private string strAuthenticationMessage { get; set; } = default(string);

            [DataMember(Name = "brandingMessage", IsRequired = false, EmitDefaultValue = false)]
            private string strBrandingMessage { get; set; } = default(string);

            //Optional. Valid only when Wave
            [DataMember(Name = "appRedirectURL", IsRequired = false, EmitDefaultValue = false)]
            private string strAppRedirectURL { get; set; } = default(string);

            public virtual bool Validate()
            {
                return strAuthChallenge.IsValid();
            }
        } //AuthenticateBaseIn

        //JSON for SP Authentication (IN)
        [DataContract]
        private class AuthenticateIn : AuthenticateBaseIn
        {
            private static AuthenticateIn CreateAuthenticate(string strType, string strInteraction)
            {
                AuthenticateIn A = new AuthenticateIn();
                A.strType        = strType;
                A.strInteraction = strInteraction;
                return A;
            }

            public static AuthenticateIn CreateAuthenticatePush(ICipheriseAuthenticatePush AuthPush, out bool bValidUserName)
            {
                string strUserName  = AuthPush.GetUserName();
                string strDeviceID  = AuthPush.GetDeviceID();

                bValidUserName = false;
                if (strUserName.IsStringValid() == false)
                    return null;

                bValidUserName = true;
                if (strDeviceID.IsStringValid() == false)
                    return null;

                AuthenticateIn A = CreateAuthenticate("Authentication", "Push");
                A.strUsername = strUserName;
                A.strDeviceID = strDeviceID;

                A.SetPushNotificationMessage(AuthPush);
                return A;

            }

            public static AuthenticateIn CreateAuthenticateWave()
            {
                AuthenticateIn A = CreateAuthenticate("Authentication", "Wave");

                return A;
            }

            //"Authentication", "Authorisation", "Sign"
            [DataMember(Name = "type")]
            public string strType { get; set; } = default(string);

            //"Authentication": "Push", "Wave"
            [DataMember(Name = "interaction")]
            public string strInteraction { get; set; } = default(string);

            //Required only when "Push"
            [DataMember(Name = "username", IsRequired = false, EmitDefaultValue = false)]
            public string strUsername { get; set; } = default(string);

            //Required only when "Push"
            [DataMember(Name = "deviceId", IsRequired = false, EmitDefaultValue = false)]
            public string strDeviceID { get; set; } = default(string);

            //AuthenticateBaseIn

            public override bool Validate()
            {
                return base.Validate();
            }
        } // AuthenticateIn

        //JSON for SP Authentication (Out)
        [DataContract]
        private class AuthenticateOut : CipheriseCommon.CipheriseError
        {
            private bool m_bWave = false;

            public void Update(bool bWave)
            {
                m_bWave = bWave;
            }

            //Valid only when BiDir.
            [DataMember(Name = "appAuthenticationURL", IsRequired = false, EmitDefaultValue = false)]
            public string strGetAppChallengeURL { get; set; } = default(string);

            //Valid always.
            [DataMember(Name = "challengeExchangeURL", IsRequired = false, EmitDefaultValue = false)]
            public string strChallengeExchangeURL { get; set; } = default(string);

            //Valid only when Wave.
            [DataMember(Name = "qrURL", IsRequired = false, EmitDefaultValue = false)]
            public string strWaveCodeURL { get; set; } = default(string);

            //Valid only when Wave + Direct.
            [DataMember(Name = "directURL", IsRequired = false, EmitDefaultValue = false)]
            public string strDirectURL { get; set; } = default(string);

            //Valid always.
            [DataMember(Name = "statusURL", IsRequired = true, EmitDefaultValue = false)]
            public string strStatusURL { get; set; } = default(string);

            //Valid when Push fails.
            [DataMember(Name = "pnErrorMessage", IsRequired = false, EmitDefaultValue = false)]
            public string strPushError { get; set; } = default(string);

            public override bool Validate()
            {
                //Always
                if (   strChallengeExchangeURL.IsNotValid()
                    || strStatusURL.IsNotValid()
                    || strGetAppChallengeURL.IsNotValid()
                    )
                    return false;

                if (m_bWave)
                {
                    if (   strWaveCodeURL.IsNotValid()
                        || strDirectURL.IsNotValid()    )
                        return false;
                }
                else //Push
                {
                    // Dont hide the error.  Allow for HasError() to report it.
                    //if (false == String.IsNullOrEmpty(strPushError))
                    //    return false;
                }

                return base.Validate();
            }

            public override bool HasError()
            {
                if (m_bWave == false)
                {
                    if (false == String.IsNullOrEmpty(strPushError))
                        return true;
                }

                return base.HasError();
            }

            public override string GetError()
            {
                if (m_bWave == false)
                {
                    if (false == String.IsNullOrEmpty(strPushError))
                        return strPushError;
                }

                return base.GetError();
            }
        } // AuthenticateOut

        //JSON for SP Authentication Status (Out)
        [DataContract]
        private class AuthenticateStatusOut : CipheriseCommon.CipheriseError
        {
            //Valid only when BiDir.
            [DataMember(Name = "statusText")]
            public string strStatusText { get; set; } = default(string);

            //Required when bBidirectional==false
            [DataMember(Name = "statusCode")]
            public int iStatusCode { get; set; } = default(int);
        } // AuthenticateStatusOut

        //JSON for SP Authentication App Challenge (Out)
        [DataContract]
        private class AuthenticateAppChallengeOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "appChallenge")]
            public string strAppChallenge { get; set; } = default(string);

            [DataMember(Name = "username")]
            public string strUsername { get; set; } = default(string);

            public override bool Validate()
            {
                return base.Validate()
                    && strAppChallenge.IsValid()
                    && strUsername.IsValid();
            }
        }  // AuthenticateAppChallengeOut

        //JSON for SP Authentication Exchange (Out)
        [DataContract]
        private class AuthenticateExchangeIn : AuthenticateBaseIn
        {
            public void SetAppSolution(string strAppSolution)
            {
                strAppChallengeSolution = strAppSolution;
            }

            public void SetError(int iError, string strError = null)
            {
                Clear();
                bError = true;
                iErrorCode = iError;
                strErrorMessage = strError;
            }

            protected override void Clear()
            {
                base.Clear();
                strAppChallengeSolution = default(string);
                bError = default(bool);
                iErrorCode = default(int);
                strErrorMessage = default(string);
            }

            public bool IsError()
            {
                return bError;
            }

            //Always valid (except  when error is set).
            [DataMember(Name = "appChallengeSolution", IsRequired = false, EmitDefaultValue = false)]
            private string strAppChallengeSolution { get; set; } = default(string);

            //AuthenticateBaseIn

            [DataMember(Name = "error", IsRequired = false, EmitDefaultValue = false)]
            private bool bError { get; set; } = default(bool);

            //800-899
            [DataMember(Name = "errorCode", IsRequired = false, EmitDefaultValue = false)]
            private int iErrorCode { get; set; } = default(int);

            [DataMember(Name = "errorMessage", IsRequired = false, EmitDefaultValue = false)]
            private string strErrorMessage { get; set; } = default(string);

            //Always valid
            [DataMember(Name = "waitForAppSolution", IsRequired = false, EmitDefaultValue = true)]
            public bool bWaitForAppSolution { get; set; } = default(bool);

            public override bool Validate()
            {
                return base.Validate()
                    && strAppChallengeSolution.IsValid();
            }
        }  // AuthenticateExchangeIn

        [DataContract]
        private class AuthenticateAppSolutionOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "authenticationSolution")]
            public string strSolution { get; set; } = default(string);

            [DataMember(Name = "authenticated")]
            public string strAuthenticated { get; set; } = default(string);

            [DataMember(Name = "deviceFriendlyName")]
            public string strDeviceName { get; set; } = default(string);

            [DataMember(Name = "deviceId")]
            public string strDeviceID { get; set; } = default(string);

            [DataMember(Name = "username")]
            public string strUserName { get; set; } = default(string);

            [DataMember(Name = "publicKey")]
            public string strPublicKey { get; set; } = default(string);

            [DataMember(Name = "publicKeyLevel")]
            public int iPubKeyLevel { get; set; } = -1;

            [DataMember(Name = "keySignature")]
            public string strKeySignature { get; set; } = default(string);

            [DataMember(Name = "payloadURL")]
            public string strPayloadURL { get; set; } = default(string);

            [DataMember(Name = "verifyAuthenticationURL")]
            public string strVerifyAuthURL { get; set; } = default(string);

            public override bool Validate()
            {
                if ((base.Validate() == false)
                    //|| strSolution.IsNotValid()
                    || strAuthenticated.IsNotValid()
                    || strDeviceName.IsNotValid()
                    || strDeviceID.IsNotValid()
                    || strUserName.IsNotValid()
                    //|| strPublicKey.IsNotValid()
                    //|| strKeySignature.IsNotValid()
                    || strPayloadURL.IsNotValid()
                    || strVerifyAuthURL.IsNotValid()
                    //|| (iPubKeyLevel <= 0)
                    )
                    return false;


                if (strAuthenticated.CompareNoCase("true"))
                {
                    return strSolution.IsValid()
                        || strPublicKey.IsValid()
                        || strKeySignature.IsValid()
                        || strSolution.IsValid()
                        || (iPubKeyLevel > 0);
                }
                return true;
            }
        } //AuthenticateAppSolution

        //JSON for SP Revoke User (IN)
        [DataContract]
        private class RevokeUserIn : CipheriseCommon.IValidate
        {
            public RevokeUserIn(string strUName, string[] astrDevIds)
            {
                strUserName   = strUName;
                astrDeviceIDs = astrDevIds;
            }

            [DataMember(Name = "username")]
            public string strUserName { get; set; }

            [DataMember(Name = "deviceIds", IsRequired = false, EmitDefaultValue = false)]
            public string[] astrDeviceIDs { get; set; }

            public bool Validate()
            {
                return strUserName.IsValid();
            }
        } // RevokeUserIn

        //JSON for SP Revoke User (OUT)
        [DataContract]
        private class RevokeUserOut : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "invalidDeviceIds", IsRequired = false, EmitDefaultValue = false)]
            public string[] astrInvalidDeviceIDs { get; set; }

            public override bool Validate()
            {
                return base.Validate();
            }
        } // RevokeUserOut

        //JSON for Auth Verify (IN)
        [DataContract]
        private class VerifyIn : CipheriseCommon.IValidate
        {
            public VerifyIn(bool bVerfiedIn, string strFailReasonIn = null)
            {
                bVerfied = bVerfiedIn;
                strFailReason = strFailReasonIn;
            }

            [DataMember(Name = "verified")]
            public bool bVerfied { get; set; }

            [DataMember(Name = "failReason", IsRequired = false, EmitDefaultValue = false)]
            public string strFailReason { get; set; } = default(string);

            public bool Validate()
            {
                return true;
            }
        } // VerifyIn

        //JSON for SP  Payload request (IN)
        [DataContract]
        private class PayloadRequest : CipheriseCommon.IValidate
        {
            public bool Init(KeyValuePairs kvpPayloadSet, string[] astrPayloadGetKeys)
            {
                if ((kvpPayloadSet != null) && (kvpPayloadSet.Count > 0))
                    aSet = kvpPayloadSet;

                if ((astrPayloadGetKeys != null) && (astrPayloadGetKeys.Length > 0))
                    astrGet = astrPayloadGetKeys;

                return (aSet != null) || (astrGet != null);
            }

            [DataMember(Name = "set", IsRequired = false, EmitDefaultValue = false)]
            public KeyValuePairs aSet { get; set; }

            [DataMember(Name = "get", IsRequired = false, EmitDefaultValue = false)]
            public string[] astrGet { get; set; }

            public bool Validate()
            {
                return ((aSet != null) && (aSet.Count > 0)) || ((astrGet != null) && (astrGet.Length > 0));
            }
        } //PayloadRequest

        //JSON for SP  Payload response (OUT)
        [DataContract]
        private class PayloadResponse : CipheriseCommon.CipheriseError
        {
            [DataMember(Name = "setResponse", IsRequired = false, EmitDefaultValue = false)]
            public bool bSet { get; set; } = default(bool);

            [DataMember(Name = "getResponse", IsRequired = false, EmitDefaultValue = false)]
            public KeyValuePairs aGet { get; set; } = default(KeyValuePairs);

            public override bool Validate()
            {
                return base.Validate();
            }
        } //PayloadResponse

        //JSON for SP Enrol and Auth Payload
        [DataContract]
        private class Payload : CipheriseCommon.IValidate
        {
            //The 'strPayloadError' is sent to the SDK caller and the App. Must be localised.
            static public Payload GeneratePayload(KeyValuePairs kvpPayloadSet, string[] astrPayloadGetKeys, CipheriseBouncyCastle BCDevice, CipheriseBouncyCastle BCServiceProvider, out string strPayloadError)
            {
                strPayloadError = null;
                string strJSONData;
                {
                    PayloadRequest PR = new PayloadRequest();
                    if (PR.Init(kvpPayloadSet, astrPayloadGetKeys) == false)
                        return null;

                    strJSONData = PR.ToJSON();
                    if (string.IsNullOrEmpty(strJSONData))
                    {
                        strPayloadError = "Payload json error."; //LOCALISE
                        return null;
                    }
                }

                //Get random AES encrypt key
                byte[] aAESKey = new byte[32];
                aAESKey.FillRandom();

                //RSA encrypt the AES key with the device public key.
                string strKeyTemp;
                if (false == BCDevice.EncryptBuffer(aAESKey, out strKeyTemp))
                {
                    strPayloadError = "Payload RSA encryption error."; //LOCALISE
                    return null;
                }

                //Encrypt Payload Data with AES key
                if (false == CipheriseBouncyCastle.AESEncryptString(ref strJSONData, aAESKey))
                {
                    strPayloadError = "Payload AES encryption error."; //LOCALISE
                    return null;
                }

                //Sign the encrypted key with the SP private key.
                string strSignatureTemp;
                if (false == BCServiceProvider.SignHexString(strKeyTemp, out strSignatureTemp))
                {
                    strPayloadError = "Payload signing error.";  //LOCALISE
                    return null;
                }

                return new Payload  { strData = strJSONData, strKey = strKeyTemp, strSignature = strSignatureTemp};
            }

            public bool ParsePayloadResponse(out PayloadResponse payloadResponse, CipheriseBouncyCastle BCDevice, CipheriseBouncyCastle BCServiceProvider)
            {
                string strError; //Sent to the SDK caller and the App.  Must be localised.
                if (Validate())
                {
                    //Verify the signature using the devices public key.
                    if (BCDevice.VerifyHexString(strKey, strSignature))
                    {
                        //RSA Decrypt the AES Key with SPs private key.
                        byte[] aAESKey;
                        if (BCServiceProvider.DecryptBuffer(strKey, out aAESKey))
                        {
                            //Decrypt Payload Data with AES key
                            string strJSONPayload = strData;
                            if (CipheriseBouncyCastle.AESDecryptString(ref strJSONPayload, aAESKey))
                            {
                                //strJSONPayload.TraceDebug("Payload response: ");
                                payloadResponse = strJSONPayload.FromJSON<PayloadResponse>();
                                if (payloadResponse != null)
                                    return payloadResponse.HasError() == false;

                                strError = "Unable to parse decrypted payload data.".TraceError(); //LOCALISE
                            }
                            else
                                strError = "Unable to decrypt payload data.".TraceError(); //LOCALISE
                        }
                        else
                            strError = "Unable to decrypt payload AES key.".TraceError(); //LOCALISE
                    }
                    else 
                        strError = "Invalid payload signature.".TraceError(); //LOCALISE
                }
                else
                    strError = "Invalid payload for parsing.".TraceError(); //LOCALISE

                payloadResponse = new PayloadResponse();
                payloadResponse.SetError(strError);
                return false;
            }

            //AES Encypted form of PayloadRequest or Payload Response.
            [DataMember(Name = "data")]
            public string strData { get; set; }

            //RSA encrypted form of the AES Key. RSA encrypted with recipients public key.
            [DataMember(Name = "key")]
            public string strKey { get; set; }

            //RSA signature of strKey. Signed using the callers private key.
            [DataMember(Name = "signature")]
            public string strSignature { get; set; }

            public bool Validate()
            {
                return strData.IsValid()
                    && strKey.IsValid()
                    && strSignature.IsValid();
            }
        }  //Payload

        //JSON for SP Enrol + Auth Confirm (IN / OUT)
        [DataContract]
        private class PayloadInOut : CipheriseCommon.CipheriseError
        {
            public PayloadInOut()  //Out
            {
                payload = null;
            }

            public PayloadInOut(Payload pl)  //In
            {
                payload = pl;
            }

            [DataMember(Name = "payload", IsRequired = false, EmitDefaultValue = false)]
            public Payload payload { get; set; }

            public override bool Validate()
            {
                return base.Validate()
                    && (payload != null);
            }
        } // PayloadInOut

        //The object passed in and returned by the alternative user enrolment methods.
        // <summary>Used by EnrolUserValidate().</summary>
        /// <summary>
        /// Used by EnrolUserValidate().
        /// </summary>
        /// <returns></returns>
        public delegate bool CanContinuePollingDelegate();

        /// <summary>
        /// This interface is to be implemented by objects being passed to <see cref="ICipheriseServiceProvider.EnrolUserInit"/>,
        /// <see cref="ICipheriseServiceProvider.EnrolUserValidate"/>, and <see cref="ICipheriseServiceProvider.EnrolUserConfirm"/>.
        /// </summary>
        public class EnrolUserReturn
        {
            /// <summary>
            /// Used by EnrolUserInit(), EnrolUserValidate(), and EnrolUserConfirm().
            /// </summary>
            public bool m_bReturn = false;

            /// <summary>
            /// Used by EnrolUserInit().
            /// </summary>
            public string m_strUserName = null;

            /// <summary>
            /// Used by EnrolUserInit() and EnrolUserValidate().
            /// </summary>
            public string m_strImageURL = null;

            /// <summary>
            /// Used by EnrolUserInit() and EnrolUserValidate().
            /// </summary>
            public string m_strNextURL = null;

            /// <summary>
            /// Used by EnrolUserInit().
            /// </summary>
            public string m_strStatusURL = null;

            /// <summary>
            /// EnrolUserInit
            /// </summary>
            public string m_strDirectURL = null;

            /// <summary>
            /// Used by EnrolUserValidate().
            /// </summary>
            public string m_strDeviceID = null;

            /// <summary>
            /// EnrolUserValidate
            /// </summary>
            public string m_strPublicKeyForPayload = null;

            /// <summary>
            /// Used by EnrolUserValidate().
            /// </summary>
            public NumberDictionary m_aSignatures = null;

            /// <summary>
            /// Used by EnrolUserValidate(). 0 for default value, -1 for long polling.
            /// </summary>
            public int m_iPollingTimeInMilliseconds = 0;

            /// <summary>
            /// Used by EnrolUserValidate().
            /// </summary>
            public CanContinuePollingDelegate CanContinuePolling = null;

            /// <summary>
            /// EnrolUserInit / EnrolUserValidate / EnrolUserConfirm. Valid when m_bReturn==false *AND* Cipherise Server returned an error.
            /// </summary>
            public string m_strCipheriseError = null;

            /// <summary>
            /// EnrolUserValidate, set when the Cipherise Server invalidates a WaveCode.
            /// </summary>
            public bool m_bWaveTimeout = false;

            /////// The following relates to Payload ///////

            /// <summary>
            /// EnrolUserConfirm (in / return)
            /// </summary>
            public KeyValuePairs m_kvpPayloadSet = null;

            /// <summary>
            /// EnrolUserConfirm (in)
            /// </summary>
            public string[] m_astrPayloadGetKeys = null;
        }

    }
}
