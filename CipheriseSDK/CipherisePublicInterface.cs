// Public interfaces for the Cipherise .Net SDK

using System.Threading.Tasks;

using NumberDictionary = System.Collections.Generic.Dictionary<string, string>;
using KeyValuePairs    = System.Collections.Generic.Dictionary<string, string>;

namespace Cipherise
{

    /// <summary>
    /// The Cipherise interface used to contact a Cipherise Server. To create an instance of a class that implements
    /// this interface, call <see cref="CipheriseSP.CreateServiceProvider"/>.
    /// </summary>
    public interface ICipheriseServiceProvider
    {
        /// <summary>
        /// Gets the ID of the Service Provider. This is a unique identifier to the Cipherise Server for this 
        /// service. All application enrolments will be bound against this id, so it is important that this 
        /// identifier is stored after Service registration.
        /// </summary>
        /// <remarks>The Service Provider ID is either passed into <see cref="CipheriseSP.CreateServiceProvider"/>
        /// or set after <see cref="Register"/> is called.</remarks>
        /// <returns>The ID of the Service Provider.</returns>
        string GetServiceProviderID();

        /// <summary>
        /// Retrieves a textual representation of the Cipherise Server version and passes it to the 
        /// <see cref="ICipheriseInfo.ServerVersion"/> method.
        /// </summary>
        /// <param name="InfoCB">An instance of a class implementing the <see cref="ICipheriseInfo"/> interface. Used to return
        /// the requested server information.</param>
        /// <returns>Boolean indicator of success.</returns>
        Task<bool> Info(ICipheriseInfo InfoCB);

        /// <summary>Determines whether the Service Provider is already registered with the Cipherise Server.</summary>
        /// <param name="Err">An instance of <see cref="ICipheriseError"/> to which error information may be provided. Can 
        /// be null.</param>
        /// <returns>Boolean indicator of whether the SP is registered.</returns>                     
        Task<bool> IsRegistered(ICipheriseError Err = null);

        /// <summary>
        /// Registers the Service Provider with the Cipherise Server and creates a Service Provider ID. Registration is required 
        /// once per service provider. Multiple services can be registered but the last one becomes the active one.
        /// </summary>
        /// <param name="strServiceProviderName">Used to specify a name for the Service Provider.</param>
        /// <param name="Err">An instance of <see cref="ICipheriseError"/> to which error information may be provided. Can be null.</param>
        /// <returns>Boolean indicator of success.</returns>
        /// <remarks>Once registered a public/private key file is created and is used internally to identify the new service 
        /// provider.
        /// It is the caller's responsibility to keep this key file secure. 
        /// The ID returned by <see cref="GetServiceProviderID"/> can be used to instantiate the same Service Provider. It 
        /// is highly recommended to store this and use this for persistence in user enrolments.
        /// If not specified, the default save location for this these keys is the local folder.</remarks>
        Task<bool> Register(string strServiceProviderName, ICipheriseError Err = null);

        /// <summary>
        /// Revokes the Service Provider's registration from the Cipherise Server. The Service Provider will be unable to 
        /// perform further actions until a new registration is made.
        /// </summary>
        /// <param name="Err">An instance of <see cref="ICipheriseError"/> to which error information may be provided. Can be null.</param>
        /// <returns>Boolean indicator of success.</returns>
        Task<bool> Revoke(ICipheriseError Err = null);

        /// <summary>
        /// Enables the requested user to enrol in the current service.
        /// </summary>
        /// <param name="EnrolUserCB">An instance of a class implementing <see cref="ICipheriseEnrolUser"/>, used so that the
        /// SDK can return enrolment details back to the Service Provider.</param>
        /// <returns>Boolean indicator of success of the call. Final enrolment status is determined by <see cref="ICipheriseEnrolUser.Enrolment"/>.</returns>
        Task<bool> EnrolUser(ICipheriseEnrolUser EnrolUserCB);

        /// <summary>
        /// Retrieves a list of devices that are registered against a username.
        /// The username is retrieved from the instantiated implementation of the <see cref="ICipheriseDevice"/> object.
        /// Upon success, the object's <see cref="ICipheriseDevice.DeviceInfo"/> will be called for each of the retrieved devices.
        /// </summary>
        /// <param name="DeviceCB">An instance of a class implementing <see cref="ICipheriseDevice"/>, used so that the
        /// SDK can query username information and return device details back to the Service Provider.</param>
        /// <returns>Boolean indicator of success.</returns>
        Task<bool> RetrieveUsersDevices(ICipheriseDevice DeviceCB);

        /// <summary>
        /// Initiates the authentication process for a user and device. The type of authentication is determined by the 
        /// implementation of <see cref="ICipheriseAuthenticate"/>, being either <see cref="ICipheriseAuthenticatePush"/> 
        /// where by a notification is sent to the user's phone or <see cref="ICipheriseAuthenticateWave"/> where the
        /// authentication is initiated by the Service Provider displaying a WaveCode, scannable by the 
        /// Cipherise application.
        /// Upon completion, <see cref="ICipheriseAuthenticate.Authenticated"/> is called with the status of the request.
        /// </summary>
        /// <remarks>The status returned by <see cref="ICipheriseAuthenticate.Authenticated"/> can either be
        /// <see cref="CipheriseAuthenticationResponse.eCAR_Accept"/> meaning the user is authenticated, 
        /// <see cref="CipheriseAuthenticationResponse.eCAR_Cancel"/> meaning the operation failed, or 
        /// <see cref="CipheriseAuthenticationResponse.eCAR_Report"/> meaning that the end user has reported the request as 
        /// fraudulent, potentially a security threat.</remarks>
        /// <param name="AuthCB">An implementation of either <see cref="ICipheriseAuthenticatePush"/> or 
        /// <see cref="ICipheriseAuthenticateWave"/>, used to provide further information for the authentication process, and
        /// to provide a means of the SDK to report back the authentication result.</param>
        /// <returns>Boolean indicator of success of the call. Final authentication status is determined by <see cref="ICipheriseAuthenticate.Authenticated"/>.</returns>
        Task<bool> Authenticate(ICipheriseAuthenticate AuthCB);

        /// <summary>
        /// Revokes the registration of a user and their devices.
        /// </summary>
        /// <param name="RevokeUserCB">An implementation of <see cref="ICipheriseRevokeUser"/> from which the SDK will 
        /// request the username and optionally specific device id's to revoke for this service.</param>
        /// <returns>Boolean indicator of success of the call.</returns>
        Task<bool> RevokeUser(ICipheriseRevokeUser RevokeUserCB);
    }

    /// <summary>
    /// This is the base interface for all of the interfaces that are implemented to interact with Cipherise.
    /// <see cref="ICipheriseError.CipheriseError(string)"/> is called to inform the Service Provider when 
    /// an error condition occurs in any of the interactions with the Cipherise Server.
    /// </summary>
    public interface ICipheriseError
    {
        /// <summary>
        /// Informs the Service Provider when an error condition occurs in any of the interactions with the 
        /// Cipherise Server.
        /// </summary>
        /// <param name="strError">The error message to pass to the Service Provider.</param>
        void CipheriseError(string strError);
    }

    /// <summary>
    /// Payload is a mechanism to store and retrieve data on the users device, per service. The calling application 
    /// can only store and retrieve data to the service it has created. Data is stored as key value pairs
    /// and could be used to store credentials, user settings, user data, etc.
    ///
    /// Only on successful enrolment (see <see cref="ICipheriseServiceProvider.EnrolUser"/>) can the calling application 'set' the payload, 
    /// while on only successful authentication (see <see cref="ICipheriseServiceProvider.Authenticate"/>) can the calling application 'set' and/or 'get' the payload.
    ///
    /// All payload data is encrypted internally when sent, retrieved and stored on the Cipherise App.
    /// </summary>
    public interface ICipherisePayload : ICipheriseError
    {
        /// <summary>
        /// Payload to send/retrieve to/from the Cipherise App.
        /// </summary>
        /// <param name="kvpSet">Key value pairs to be sent to the Cipherise App. Set to <c>null</c> for no payload.</param>
        /// <param name="astrGetKeys">Key names to be retrieved from the Cipherise App. Set to <c>null</c> for no payload.</param>
        void PayloadToSend(ref KeyValuePairs kvpSet, ref string[] astrGetKeys);

        /// <summary>
        /// Payload retrieved from the Cipherise App.
        /// </summary>
        /// <param name="kvpGet">Key value pairs retrieved from the Cipherise App.</param>
        /// <returns>Return true to accept the retrieved payload, otherwise false which will cancel the enrolment or authentication.</returns>
        bool PayloadResponseFromApp(KeyValuePairs kvpGet);
    }

    /// <summary>
    /// This is the interface containing all required methods to interact with Cipherise for the Enrolment Process
    /// through the calling of <see cref="ICipheriseServiceProvider.EnrolUser"/>.
    /// </summary>
    public interface ICipheriseEnrolUser : ICipherisePayload
    {
        /// <summary>
        /// Called by the SDK to determine the username to enrol to this Service.
        /// The username must be unqiue to the service.
        /// </summary>
        /// <returns>The username to enrol to this Service.</returns>
        string GetUserName();

        /// <summary>
        /// Called by the SDK when a WaveCode is ready to be displayed and scanned by the user.
        /// </summary>
        /// <param name="strWaveCodeURL">The URL to where the WaveCode is located.</param>
        /// <returns>Return false to cancel the enrolment.</returns>
        bool DisplayWaveCode(string strWaveCodeURL);

        /// <summary>
        /// Called by the SDK when an identicon is to be displayed and matched by the user.
        /// The calling application should at this point prompt the user for confimration of matching
        /// identicon images and return the result. 
        /// </summary>
        /// <param name="strIdenticonURL">The URL to where the identicon image is located.</param>
        /// <returns>Return true if the identicons match, otherwise false which cancels the enrolment.</returns>
        bool DisplayIdenticon(string strIdenticonURL);

        /// <summary>
        /// Direct Enrolment is used in the sceneratio where the user is trying to enrol themselves, on the same device 
        /// where the Cipherise App is installed.  In this scenario the user can't scan the WaveCode. To overcome this
        /// a button should be displayed to the user, that when clicked, browses to the URL, allowing switching to and 
        /// from the Cipherise App.
        /// Called by the SDK when the Direct Enrolment URL is ready to be used, and should be displayed to the user as a
        /// button (either as a HTML button or native OS).
        /// </summary>
        /// <param name="strDirectURL">
        /// The URL to present to the user as an alternative to a WaveCode.
        /// To switch to the Cipherise App the URL must be prepended with <c>cipherise://?directEnrolURL=</c>.
        /// </param>
        /// <returns>Return true to continue the enrolment, otherwise return false to cancel the enrolment.</returns>
        bool DisplayDirectURL(string strDirectURL);

        /// <summary>
        /// Called by SDK to determine if a new enrolment request should occur when a timeout occurs.
        /// Typical behaviour is for an enrolment to return true.
        /// </summary>
        /// <returns>An indicator of whether an enrolment should be re-requested upon timeout.</returns>
        bool RepeatOnTimeout();

        /// <summary>
        /// Called by SDK when enrolment has completed, advising the Service of enrolment information.
        /// It is at this point that the enrolment process is considered complete.
        /// </summary>
        /// <param name="bConfirmed">Boolean confirmation indicator of enrolment success.</param>
        /// <param name="strUserName">The username that was enrolled. May be null or empty when bConfirmed is false.</param>
        /// <param name="strDeviceID">The device id that was enrolled. May be null or empty when bConfirmed is false.</param>
        void Enrolment(bool bConfirmed,  string strUserName, string strDeviceID);

        /// <summary>
        /// Called by the SDK to determine the polling frequency for checking the enrolment status.
        /// </summary>
        /// <returns>
        /// The polling time in milliseconds. 
        /// Returning 0 sets polling to the default value of 3000 milliseconds and returning -1 will initiate long polling, internally
        /// blocking until the enrolment is complete or a timeout occurs.
        /// </returns>
        int GetPollTimeInMilliseconds();

        /// <summary>
        /// Called by the SDK to determine if short polling of the enrolment status should continue.
        /// </summary>
        /// <returns>An indicator of whether polling of the Wave enrolment should continue.</returns>
        bool CanContinuePolling();
    }

    /// <summary>
    /// An interface defining the methods required by the SDK to provide device information for an individual user to 
    /// the application calling <see cref="ICipheriseServiceProvider.RetrieveUsersDevices"/>.
    /// </summary>
    public interface ICipheriseDevice : ICipheriseError
    {
        /// <summary>
        /// Called by the SDK to determine whose devices should be queried.
        /// </summary>
        /// <returns>The username of the enrolled user to be queried.</returns>
        string GetUserName();

        /// <summary>
        /// Called to determine if unauthorised/revoked devices should be queried.
        /// </summary>
        /// <returns>True if unauthorised/revoked devices should be queried, otherwise false.</returns>
        bool IncludeUnauthorisedDevices();

        /// <summary>Called for each device belonging to the user.</summary>
        /// <param name="strDeviceName">The name of the device.</param>
        /// <param name="strDeviceID">The id of the device.</param>
        /// <param name="bAuthorised">An indication of whether the device is authorised.</param>
        /// <returns>Return true if more devices are required, otherwise return false to stop the callback.</returns>
        bool DeviceInfo(string strDeviceName, string strDeviceID, bool bAuthorised);
    }

    /// <summary>
    /// An interface defining the methods required by the SDK to provide Cipherise Server information to the application 
    /// calling <see cref="ICipheriseServiceProvider.Info"/>.
    /// </summary>
    public interface ICipheriseInfo : ICipheriseError
    {
        /// <summary>
        /// Provides the Cipherise Server version to the caller of <see cref="ICipheriseServiceProvider.Info"/>.
        /// </summary>
        /// <param name="strServerVersion">The Cipherise Server version.</param>
        void ServerVersion(string strServerVersion);
    }

    /// <summary>
    /// An enumeration to describe the possible authentication types that could be sent to the Cipherise application.
    /// </summary>
    public enum CipheriseAuthenticationType
    {
        /// <summary>
        /// Level 1 Authentication - Notification type. Requires the Cipherise application to be opened and authentication 
        /// acknowledged.
        /// </summary>
        eCAT_AuthNotification = 1,
        /// <summary>
        /// Level 2 Authentication - Approval type. Interaction by user required in the Cipherise application to approve, cancel 
        /// or report.
        /// </summary>
        eCAT_AuthApproval = 2,
        /// <summary>
        /// Level 3 Authentication - Biometric type. Interaction by user required in the Cipherise application to apply a biometric
        /// input (finger print or face), or cancel or report. Note that if the device the Cipherise application is running
        /// on does not have the necessary hardware or if it is disabled, this will be elevated to <see cref="eCAT_AuthOneTiCK"/>.
        /// </summary>
        eCAT_AuthBiometric = 3,
        /// <summary>
        /// Level 4 Authentication - OneTiCK type. Interaction by user required in the Cipherise application to solve the 
        /// OneTiCK (One Time Cognitive Keyboard) challenge, or cancel or report.
        /// </summary>
        eCAT_AuthOneTiCK = 4
    };

    /// <summary>
    /// An enumeration to describe the possible Authentication responses from the Cipherise application.
    /// </summary>
    public enum CipheriseAuthenticationResponse
    {
        /// <summary>
        /// Indicates that the authentication was successful.
        /// </summary>
        eCAR_Accept,
        
        /// <summary>
        /// Indicates that the authentication was cancelled by the Cipherise application user.
        /// </summary>
        eCAR_Cancel,

        /// <summary>
        /// Indicates that the Cipherise application user has reported the authentication, cancelling the authentication and 
        /// informing the Cipherise Server that followup action should be taken. 
        /// </summary>
        eCAR_Report
    };

    /// <summary>
    /// This interface is NOT to be directly implemented. It is subclassed by <see cref="ICipheriseAuthenticatePush"/> and
    /// <see cref="ICipheriseAuthenticateWave"/>. It contains the common methods to be invoked by the SDK to retrieve required
    /// information for <see cref="ICipheriseServiceProvider.Authenticate"/> and also provides methods for the SDK to return
    /// resultant authentication information.
    /// </summary>
    public interface ICipheriseAuthenticate : ICipherisePayload
    {
        /// <summary>
        /// Called by the SDK to determine which authentication type to send to the device. It must be one of 
        /// <see cref="CipheriseAuthenticationType.eCAT_AuthNotification"/> or <see cref="CipheriseAuthenticationType.eCAT_AuthApproval"/> or
        /// <see cref="CipheriseAuthenticationType.eCAT_AuthBiometric"/> or <see cref="CipheriseAuthenticationType.eCAT_AuthOneTiCK"/>.
        /// </summary>
        /// <returns>The authentication type to send to the Cipherise Application.</returns>
        CipheriseAuthenticationType GetAuthenticationType();

        /// <summary>
        /// Called by the SDK to query what authentication message to send to the device.
        /// </summary>
        /// <returns>The authentication message.</returns>
        string GetAuthenticationMessage();

        /// <summary>
        /// Called by the SDK to query what branding message to send to the device.
        /// </summary>
        /// <returns>The branding message. This can be null or empty when no branding is required.</returns>
        string GetBrandingMessage();

        /// <summary>
        /// Called by the SDK to determine the polling frequency for checking the authentication status.
        /// </summary>
        /// <returns>
        /// The polling time in milliseconds. 
        /// Returning 0 sets polling to the default value of 3000 milliseconds and returning -1 will initiate long polling, internally
        /// blocking until the authentication is complete or a timeout occurs.
        /// </returns>
        int GetPollTimeInMilliseconds();

        /// <summary>
        /// Called by the SDK to determine if short polling of the authentication status should continue.
        /// </summary>
        /// <returns>An indicator of whether polling of the Authentication should continue.</returns>
        bool CanContinuePolling();

        /// <summary>
        /// Called by the SDK when an authentication is pending an action on the Cipherise App.
        /// This allows the calling application to display an alternative user experience or instructions.
        /// </summary>
        void WaitingForCipheriseApp();

        /// <summary>
        /// Called by the SDK when the Cipherise App has determined the username. The calling application can then
        /// format the authentication type, authentication and/or branding messages accordingly.
        /// </summary>
        /// <param name="strUserName">The authenticating user's registered username.</param>
        void CipheriseAppDetails(string strUserName);

        /// <summary>
        /// Called by SDK to determine if a new authentication request should occur when a timeout occurs.
        /// Typical behaviour is for a Push Authentication to return false, but a Wave Authentication to return true.
        /// </summary>
        /// <returns>An indicator of whether an authentication should be re-requested upon timeout.</returns>
        bool RepeatOnTimeout();

        /// <summary>
        /// Called by the SDK when the authentication process has completed, passing the implementing application the result
        /// of the authentication.
        /// Username and device information returned when applicable.
        /// </summary>
        /// <param name="eResponse">The result of the authentication. 
        /// <see cref="CipheriseAuthenticationResponse.eCAR_Accept"/>, indicates successful authentication,
        /// <see cref="CipheriseAuthenticationResponse.eCAR_Cancel"/>, indicates that the Cipherise application user has cancelled 
        /// the authentication,
        /// <see cref="CipheriseAuthenticationResponse.eCAR_Report"/>, indicates that the Cipherise application user has reported the 
        /// authentication, cancelling the authentication and informing the Cipherise Server that followup action should be taken.
        /// </param>
        /// <param name="strUserName">The username of the authenticating user. When using Wave Authentication, this is not
        /// known at the start of the authentication process.</param>
        /// <param name="strDeviceName">The device name of the authenticating user. When using Wave Authentication, this is not 
        /// known at the start of the authentication process. This is used to provide some differentiation between devices for
        /// a user, as they may have more than one device registered to a service.</param>
        /// <param name="strDeviceID">The device id of the authenticating user. When using Wave Authentication, this is not 
        /// known at the start of the authentication process. This is used to provide some differentiation between devices for
        /// a user, as they may have more than one device registered to a service.</param>
        void Authenticated(CipheriseAuthenticationResponse eResponse,
                           string strUserName, string strDeviceName, string strDeviceID); 
    }

    /// <summary>
    /// An interface defining the methods required by the SDK to retrieve the extra information needed for a Push Authentication.
    /// See <see cref="ICipheriseAuthenticate"/> and <see cref="ICipheriseServiceProvider.Authenticate"/> for further information.
    /// </summary>
    public interface ICipheriseAuthenticatePush : ICipheriseAuthenticate
    {
        /// <summary>
        /// Called by the SDK to determine which user should be authenticated.
        /// </summary>
        /// <returns>The username to send the authentication to.</returns>
        string GetUserName();

        /// <summary>
        /// Called by the SDK to determine which device should be used for authentication.
        /// Device ids can be retrieved by <see cref="ICipheriseServiceProvider.RetrieveUsersDevices"/>.
        /// </summary>
        /// <returns>The device id of the device to send the authentication to.</returns>
        string GetDeviceID();

        /// <summary>
        /// Called by the SDK to determine the notification message to send to the device. This message is
        /// displayed in the devices OS notication area, not within the Cipherise App.
        /// </summary>
        /// <returns>The actual notification message to send with the authentication.</returns>
        string GetNotificationMessage();
    }

    /// <summary>
    /// An interface defining the methods required by the SDK to retrieve the extra information needed for a Wave Authentication.
    /// See <see cref="ICipheriseAuthenticate"/> and <see cref="ICipheriseServiceProvider.Authenticate"/> for further information.
    /// </summary>
    public interface ICipheriseAuthenticateWave : ICipheriseAuthenticate
    {
        /// <summary>
        /// Called by the SDK when a WaveCode is ready to be displayed and scanned by the user.
        /// </summary>
        /// <param name="strWaveCodeURL">The URL to where the WaveCode is located.</param>
        /// <returns>Boolean indicator of success.</returns>
        /// <returns>Return true to continue the authentication, otherwise return false to cancel the authentication.</returns>
        bool DisplayWaveCode(string strWaveCodeURL);

        /// <summary>
        /// Direct Authentication is used in the scenerio where the user is trying to authenticate themselves on the same
        /// device where the Cipherise App is installed.  In this scenario the user can't scan the WaveCode. To overcome this,
        /// a button should be displayed to the user, that when clicked, browses to the URL, allowing switching to and from the
        /// Cipherise App.
        /// Called by the SDK when the Direct Authentication URL is ready to be used, and should be displayed to the user as a
        /// button (either as a HTML button or native OS).
        /// </summary>
        /// <param name="strDirectURL">
        /// The URL to present to the user as an alternative to a WaveCode.
        /// To switch to the Cipherise App the URL must be prepended with <c>cipherise://?directAuthURL=</c>.
        /// </param>
        /// <returns>Return true to continue the authentication, otherwise return false to cancel the authentication.</returns>
        bool DisplayDirectURL(string strDirectURL);

        /// <summary>
        /// This is required when Direct Authentication is used. It is called by the SDK to inform the Cipherise App on 
        /// how to switch back to the calling app. It can be null or empty to trigger native OS behaviour.
        /// </summary>
        /// <returns>The calling applications unique URL. 
        /// For further reading see the <a href="https://developer.android.com/training/app-links/deep-linking">Android</a> 
        /// or <a href="https://developer.apple.com/documentation/uikit/inter-process_communication/allowing_apps_and_websites_to_link_to_your_content/defining_a_custom_url_scheme_for_your_app">iOS</a> documentation.
        /// </returns>
        string GetRedirectURL();
    }

    /// <summary>
    /// An interface defining the methods required by the SDK to retrieve the information needed to revoke a user.
    /// See <see cref="ICipheriseServiceProvider.RevokeUser"/>.
    /// </summary>
    public interface ICipheriseRevokeUser : ICipheriseError
    {
        /// <summary>
        /// Called by the SDK to determine which user should be revoked.
        /// </summary>
        /// <returns>The username of the user to revoke.</returns>
        string GetUserName();

        /// <summary>
        /// Called by the SDK to determine which devices should be revoked for the user. Supplying <c>null</c> will 
        /// revoke all the user's devices.
        /// Device ids can be retrieved by <see cref="ICipheriseServiceProvider.RetrieveUsersDevices"/>.
        /// </summary>
        /// <returns>An array of the specific device id's, as given by the Cipherise Server, to revoke.</returns>
        string[] GetDeviceIDs();

        /// <summary>
        /// Called by the SDK to inform the application when 
        /// <see cref="ICipheriseServiceProvider.RevokeUser(ICipheriseRevokeUser)"/> has been requested but an invalid ID was 
        /// supplied by <see cref="GetDeviceIDs"/>.
        /// </summary>
        /// <param name="astrInvalidDeviceIDs">An array of the invalid device ids.</param>
        void SetInvalidIDs(string[] astrInvalidDeviceIDs);
    }
}