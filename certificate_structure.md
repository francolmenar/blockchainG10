# Certificate specifications

## Certificate format

```json
{
  "dateIssued": "dd/mm/yyyy",
  "dateExpired": "dd/mm/yyyy",
  "level": "1",
  "certificateName": "Bachelor in Computer Science & Engineering",
  "issuerName": "University of Twente",
  "issuedName": "Francisco Colmenar"
}
```

## Transaction payload format

`<action>,<identifier>,<certificate json base64-encoded>`

### _Action_
The value can be:
  - `create`
  - `edit`
  - `delete`
but only `create` is implemented, the using the other will raise an exception.

### _Identifier_
It is used to compute the address of the certificate.
An option is to use `identifier = sha512(issuedName+issuerName)` but it is still not enforced.

### _Certificate json hex-encoded_
It is the certificate json, which must contain the fields specified above, base64-encoded.
