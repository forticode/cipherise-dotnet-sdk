### Advanced Features  

Payload is a feature where a Service Provider can encrypt and send data to a user's device
for storage via an authentication or at enrolment, and then retrieved from the user's device when 
required via an authentication. Each individual payload has a maximum size of 4k bytes.
Ideally, this would be used by a Service Provider, such that any private or sensitive user data that the 
Service Provider requires could be held at rest on the user's own device rather than held collectively at
the Service Provider's storage where the consequences of a hack are far further reaching.
Examples of where payload could be used include credit card payment details for a regularly used
service, address details or other personally identifying details.
  * [Payload](#Payload)