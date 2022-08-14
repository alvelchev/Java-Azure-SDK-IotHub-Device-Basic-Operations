package org.azure.exampels;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
public class RegisterNewDeviceAzureHub {
    private static final Logger LOG = LoggerFactory.getLogger(RegisterNewDeviceAzureHub.class);

    public static void main(String[] args) {
        //scopeId is taken from AzureDeviceProvisioningService --> Overview
        //deviceId of the new device
        var c = generateDeviceRegistrationToken("cXdlX3F3ZV9xX3F3ZQ", "0ne002EE24E");
        System.out.println(c);
    }

    public static String generateDeviceRegistrationToken(String deviceId, String scopeId) {
        return buildAzureSasToken(deviceId, composeDeviceRegistrationUrl(deviceId, scopeId));
    }

    public static String composeDeviceRegistrationUrl(String deviceId, String scopeId) {
        LOG.info("composeDeviceRegistrationUrl: " + String.format(Constants.REGISTRATION_SCOPE, scopeId, deviceId));
        return String.format(Constants.REGISTRATION_SCOPE, scopeId, deviceId);
    }

    public static String buildAzureSasToken(String deviceId, String azureUrl) {
        // Symmetrick key is the primary key of the enrollment group
        String token = null;
        try {
            String keyValue =
                    getDeviceKeyValue1(
                            deviceId,
                            "OLCc1142LREdkcFM4hcrJMKplXGe3mw0F2395KfmAXYemroeCatAWqMGEj4Yoe7owEY/vze5mh6iJlz7Q7hfiw==");
            String targetUrlEncoded =
                    URLEncoder.encode(azureUrl.toLowerCase(Locale.ENGLISH), UTF_8.name());
            String toSign = targetUrlEncoded + "\n" + getExpiry();
            token = buildSasToken(targetUrlEncoded, keyValue, toSign);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException e) {
            LOG.warn(e.getMessage(), e);
        }
        LOG.info("buildAzureSasToken1: " + token);
        return token;
    }

    private static String buildSasToken(String targetUri, String keyValue, String toSign) {
        String token = null;
        try {
            byte[] rawHmac = constructRawHmac(keyValue, toSign);
            String signature =
                    URLEncoder.encode(Base64.getEncoder().encodeToString(rawHmac), UTF_8.name());
            token = String.format(Constants.SAS_TOKEN_FORMAT, targetUri, signature, getExpiry());
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException ex) {
            LOG.warn(ex.getMessage(), ex);
        }
        return token;
    }

    private static byte[] constructRawHmac(String keyValue, String toSign)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        byte[] keyBytes = Base64.getDecoder().decode(keyValue.getBytes(UTF_8.name()));
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, Constants.HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(Constants.HMAC_ALGORITHM);
        mac.init(signingKey);
        return mac.doFinal(toSign.getBytes(UTF_8.name()));
    }

    private static String getDeviceKeyValue1(String encoded, String symmetricKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] decodedKey = Base64.getDecoder().decode(symmetricKey);
        validateSignature(encoded, decodedKey);
        byte[] derivedDeviceKey = hmacSignData(encoded.getBytes(UTF_8), decodedKey);
        return Base64.getEncoder().encodeToString(derivedDeviceKey);
    }

    private static byte[] hmacSignData(byte[] signature, byte[] base64DecodedKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKey = new SecretKeySpec(base64DecodedKey, Constants.HMAC_ALGORITHM);
        Mac hmacSha256 = Mac.getInstance(Constants.HMAC_ALGORITHM);
        hmacSha256.init(secretKey);
        return hmacSha256.doFinal(signature);
    }

    private static void validateSignature(String encoded, byte[] decodedKey)
            throws NoSuchAlgorithmException {
        boolean isValidSignature =
                encoded.length() != 0 && decodedKey != null && decodedKey.length != 0;
        if (!isValidSignature) {
            throw new NoSuchAlgorithmException("Signature or Key cannot be null or empty");
        }
    }

    private static Long getExpiry() {
        return LocalDateTime.now(ZoneOffset.UTC).plusMinutes(5).toEpochSecond(ZoneOffset.UTC);
    }

}