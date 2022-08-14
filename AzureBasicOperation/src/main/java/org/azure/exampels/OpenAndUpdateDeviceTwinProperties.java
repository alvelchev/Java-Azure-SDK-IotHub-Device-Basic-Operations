package org.azure.exampels;

import com.microsoft.azure.sdk.iot.device.DeviceClient;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.Property;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;


import static java.nio.charset.StandardCharsets.UTF_8;
public class OpenAndUpdateDeviceTwinProperties {

    public static void main(String[] args) throws IOException, InterruptedException {
        // deviceId which data we want
        initializeDeviceClient1("c61075aa-60e2-5d0f-9bf4-d377afc1cbe6");
    }

    public static void initializeDeviceClient1(String deviceId) throws IOException, InterruptedException {
        String sasToken =
                generateDeviceTwinUpdateToken1(
                        //iot hub name where device is
                        deviceId, "iothub-iomt-iothub-v1-dev-westeurope.azure-devices.net");

        DeviceClient deviceClient = null;
        try {
            deviceClient = new DeviceClient(sasToken, Constants.PROTOCOL);
            deviceClient.open();
            Thread.sleep(2000);
            deviceClient.startDeviceTwin(
                    new DeviceTwinStatusCallBack(), null, new OnPropertyChange(), null);
            var reportedProperties = new HashMap<String, Object>();
            reportedProperties.put(Constants.ACTIVE, Constants.ACTIVE_VALUE_FALSE);
            Set<Property> properties = getTwinReportedProperties(reportedProperties);
            deviceClient.sendReportedProperties(properties);
            Thread.sleep(2000);
        } catch (URISyntaxException ex) {
        } finally {
            if (deviceClient != null) {
                deviceClient.closeNow();
            }
        }
    }

    public static String generateDeviceTwinUpdateToken1(String deviceId, String iomtHubEndPoint) {
        String sasToken =
                buildAzureSasToken1(
                        deviceId, composeIotHubUrl1(deviceId, iomtHubEndPoint));
        return composeDeviceTwinUpdateUrl1(deviceId, sasToken, iomtHubEndPoint);
    }

    public static String buildAzureSasToken1(String deviceId, String azureUrl) {
        String token = null;
        try {
            // symmetric key is taken from the primary key of the enrollment group
            String keyValue = getDeviceKeyValue1(deviceId, "OLCc1142LREdkcFM4hcrJMKplXGe3mw0F2395KfmAXYemroeCatAWqMGEj4Yoe7owEY/vze5mh6iJlz7Q7hfiw==");
            String targetUrlEncoded =
                    URLEncoder.encode(azureUrl.toLowerCase(Locale.ENGLISH), UTF_8.name());
            String toSign = targetUrlEncoded + "\n" + getExpiry1();
            token = buildSasToken1(targetUrlEncoded, keyValue, toSign);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException e) {
            System.out.printf(e.getMessage(), e);
        }
        return token;
    }

    public static String composeIotHubUrl1(String deviceId, String iomtHubEndPoint) {
        String endPoint = iomtHubEndPoint.concat(Constants.HUB_ENDPOINT_PREFIX);
        return String.format(endPoint, deviceId);
    }

    public static String composeDeviceTwinUpdateUrl1(
            String deviceId, String sasToken, String iomtHubEndPoint) {
        return String.format(
                Constants.SAS_CONNECTION_STRING_FORMAT, iomtHubEndPoint, deviceId, sasToken);
    }

    private static String getDeviceKeyValue1(String encoded, String symmetricKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] decodedKey = Base64.getDecoder().decode(symmetricKey);
        validateSignature1(encoded, decodedKey);
        byte[] derivedDeviceKey = hmacSignData1(encoded.getBytes(UTF_8), decodedKey);
        return Base64.getEncoder().encodeToString(derivedDeviceKey);
    }
    private static void validateSignature1(String encoded, byte[] decodedKey)
            throws NoSuchAlgorithmException {
        boolean isValidSignature =
                encoded.length() != 0 && decodedKey != null && decodedKey.length != 0;
        if (!isValidSignature) {
            throw new NoSuchAlgorithmException("Signature or Key cannot be null or empty");
        }
    }
    private static byte[] hmacSignData1(byte[] signature, byte[] base64DecodedKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKey = new SecretKeySpec(base64DecodedKey, Constants.HMAC_ALGORITHM);
        Mac hmacSha256 = Mac.getInstance(Constants.HMAC_ALGORITHM);
        hmacSha256.init(secretKey);
        return hmacSha256.doFinal(signature);
    }
    private static Long getExpiry1() {
        return LocalDateTime.now(ZoneOffset.UTC).plusMinutes(5).toEpochSecond(ZoneOffset.UTC);
    }

    private static String buildSasToken1(String targetUri, String keyValue, String toSign) {
        String token = null;
        try {
            byte[] rawHmac = constructRawHmac1(keyValue, toSign);
            String signature =
                    URLEncoder.encode(Base64.getEncoder().encodeToString(rawHmac), UTF_8.name());
            token = String.format(Constants.SAS_TOKEN_FORMAT, targetUri, signature, getExpiry1());
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException ex) {
        }
        return token;
    }

    private static byte[] constructRawHmac1(String keyValue, String toSign)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        byte[] keyBytes = Base64.getDecoder().decode(keyValue.getBytes(UTF_8.name()));
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, Constants.HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(Constants.HMAC_ALGORITHM);
        mac.init(signingKey);
        return mac.doFinal(toSign.getBytes(UTF_8.name()));
    }

    public static Set<Property> getTwinReportedProperties(Map<String, Object> reportedProperties) {
        Set<Property> twinReportedProperties = new LinkedHashSet<>();
        reportedProperties.forEach(
                (key, value) -> twinReportedProperties.add(new Property(key, value)));
        return twinReportedProperties;
    }
}