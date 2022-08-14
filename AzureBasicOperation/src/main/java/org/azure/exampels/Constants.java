package org.azure.exampels;


import com.microsoft.azure.sdk.iot.device.IotHubClientProtocol;

import java.util.List;
import java.util.UUID;

public final class Constants {
  public static final String HUB_ENDPOINT_PREFIX = "/devices/%s";

  public static final String ACTIVE = "active";
  public static final Boolean ACTIVE_VALUE_FALSE = Boolean.TRUE;
  public static final String HMAC_ALGORITHM = "HmacSHA256";

  /* PROTOCOLS */
  public static final IotHubClientProtocol PROTOCOL = IotHubClientProtocol.AMQPS_WS;
  public static final String SAS_TOKEN_FORMAT = "SharedAccessSignature sr=%s&sig=%s&se=%s";
  public static final String REGISTRATION_SCOPE = "%s/registrations/%s";
  public static final String SAS_CONNECTION_STRING_FORMAT =
      "HostName=%s;CredentialType=SharedAccessSignature;DeviceId=%s;SharedAccessSignature=%s";
  private Constants() {}
}
