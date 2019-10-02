### <a name="EnrolUser"></a>Enrolling a user to a service
To enrol a user into a service the follow steps need to occur:

1. The Service Provider calls 
[ICipheriseServiceProvider.EnrolUser()](../api/Cipherise.ICipheriseServiceProvider.html#Cipherise_ICipheriseServiceProvider_EnrolUser_Cipherise_ICipheriseEnrolUser_).

2. The SDK informs the Service Provider via
[ICipheriseEnrolUser::DisplayWaveCode()](../api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_DisplayWaveCode_System_String_)
that an enrolment WaveCode is ready to be presented to the user.

3. The user scans the WaveCode with the Cipherise App.

4. The SDK informs the Service Provider via
[ICipheriseEnrolUser::DisplayIdenticon()](../api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_DisplayIdenticon_System_String_)
that an identicon is ready to be presented to the user.

5. The Service Provider asks the user to confirm that the identicon presented on their device matches the one from step 4. If it does match
[ICipheriseEnrolUser::DisplayIdenticon()](../api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_DisplayIdenticon_System_String_)
should return true, otherwise false to cancel the enrolment.

6. The SDK informs the Service Provider via
[ICipheriseEnrolUser::Enrolment()](../api/Cipherise.ICipheriseEnrolUser.html#Cipherise_ICipheriseEnrolUser_Enrolment_System_Boolean_System_String_System_String_)
whether the enrolment was successful.

The above steps can be shown here:
[!code[ENROL_USER_CODE](enroluser.cs)]
