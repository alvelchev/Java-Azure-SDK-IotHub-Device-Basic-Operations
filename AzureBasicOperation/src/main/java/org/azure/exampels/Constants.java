package org.azure.exampels;


import com.microsoft.azure.sdk.iot.device.IotHubClientProtocol;

public final class Constants {
    public static final String HUB_ENDPOINT_PREFIX = "/devices/%s";

    public static final String ACTIVE = "active";
    public static final String DEVICE_ID = "cXdlX3F3ZV9xX3F3ZQ";
    public static final String ENROLLMENT_SCOPE_ID = "0ne002EE24E";
    public static final String SYMMETRICK_KEY_PRIMARY_KEY_ENROLLMENT_GROUP =
            "OLCc1142LREdkcFM4hcrJMKplXGe3mw0F2395KfmAXYemroeCatAWqMGEj4Yoe7owEY/vze5mh6iJlz7Q7hfiw==";
    public static final String IOT_HUB_NAME = "iothub-iomt-iothub-v1-dev-westeurope.azure-devices.net";

    public static final Boolean ACTIVE_VALUE_FALSE = Boolean.TRUE;
    public static final String HMAC_ALGORITHM = "HmacSHA256";

    /* PROTOCOLS */
    public static final IotHubClientProtocol PROTOCOL = IotHubClientProtocol.AMQPS_WS;
    public static final String SAS_TOKEN_FORMAT = "SharedAccessSignature sr=%s&sig=%s&se=%s";
    public static final String PROVISIONING_ENDPOINT = "https://global.azure-devices-provisioning.net";
    public static final String REGISTRATION_SCOPE = "%s/registrations/%s";
    public static final String SAS_CONNECTION_STRING_FORMAT =
            "HostName=%s;CredentialType=SharedAccessSignature;DeviceId=%s;SharedAccessSignature=%s";
    public static final String PROVISIONING_SERVICE_URL =
            "%s/%s/registrations/%s/register?api-version=2018-11-01";

    private Constants() {}
}
