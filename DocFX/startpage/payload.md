### <a name="Payload"></a>Payload

Payload data can be supplied to the user's device during 
[enrolment](#EnrolUser)
and supplied and fetched during 
[push](#PushAuth)
and 
[wave](#WaveAuth)
authentication. 

Payload data is arbitrary and is controlled by the Service Provider. 
All payload data is internally encrypted when supplied to and fetched from the users device.

Payload data is accessed by declaring a class that implements the 
[ICipherisePayload](../api/Cipherise.ICipherisePayload.html).
interface: 
[!code[PAYLOAD_CODE](payload.cs)]