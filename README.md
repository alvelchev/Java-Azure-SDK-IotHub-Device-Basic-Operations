[![Java CI with Maven](https://github.com/alvelchev/Java-Azure-SDK-IotHub-Device-Basic-Operations/actions/workflows/maven.yml/badge.svg)](https://github.com/alvelchev/Java-Azure-SDK-IotHub-Device-Basic-Operations/actions/workflows/maven.yml)

# JavaAzureIotBasicOperations
This is a java spring boot application which provides functionality to open, update and delete device twin using azure java sdk from AzureIoT hub

# SAS token structure

A token signed with a shared access key grants access to all the functionality associated with the shared access policy permissions. A token signed with a device identity's symmetric key only grants the DeviceConnect permission for the associated device identity.

A SAS token has the following format:

```java
SharedAccessSignature sig={signature-string}&se={expiry}&skn={policyName}&sr={URL-encoded-resourceURI}
```


Here are the expected values:

| Value | Description |
| --- | --- |
| {signature} | An HMAC-SHA256 signature string of the form: {URL-encoded-resourceURI} + "\n" + expiry. Important: The key is decoded from base64 and used as key to perform the HMAC-SHA256 computation. |
| {resourceURI} | 	URI prefix (by segment) of the endpoints that can be accessed with this token, starting with host name of the IoT hub (no protocol). SAS tokens granted to backend services are scoped to the IoT hub-level; for example, myHub.azure-devices.net. SAS tokens granted to devices must be scoped to an individual device; for example, myHub.azure-devices.net/devices/device1. |
| {expiry}| UTF8 strings for number of seconds since the epoch 00:00:00 UTC on 1 January 1970. |
| {URL-encoded-resourceURI} | Lower case URL-encoding of the lower case resource URI |
| {policyName} | The name of the shared access policy to which this token refers. Absent if the token refers to device-registry credentials. |


The following code generates a SAS token using the resource URI and signing key. The expiration period is set to one hour from the current time. The next sections detail how to initialize the different inputs for the different token use cases.

```java
    public static String generateSasToken(String resourceUri, String key) throws Exception {
        // Token will expire in one hour
        var expiry = Instant.now().getEpochSecond() + 3600;

        String stringToSign = URLEncoder.encode(resourceUri, StandardCharsets.UTF_8) + "\n" + expiry;
        byte[] decodedKey = Base64.getDecoder().decode(key);

        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "HmacSHA256");
        sha256HMAC.init(secretKey);
        Base64.Encoder encoder = Base64.getEncoder();

        String signature = new String(encoder.encode(
            sha256HMAC.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);

        String token = "SharedAccessSignature sr=" + URLEncoder.encode(resourceUri, StandardCharsets.UTF_8)
                + "&sig=" + URLEncoder.encode(signature, StandardCharsets.UTF_8.name()) + "&se=" + expiry;
            
        return token;
    }
```


<b>Here are the main steps of the token service pattern:</b>


![alt text](https://learn.microsoft.com/en-us/azure/iot-hub/media/iot-hub-devguide-security/tokenservice.png)
