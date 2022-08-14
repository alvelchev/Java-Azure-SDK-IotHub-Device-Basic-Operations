package org.azure.exampels;

import com.microsoft.azure.sdk.iot.device.IotHubEventCallback;
import com.microsoft.azure.sdk.iot.device.IotHubStatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DeviceTwinStatusCallBack implements IotHubEventCallback {

    private static final Logger LOG = LoggerFactory.getLogger(DeviceTwinStatusCallBack.class);

    @Override
    public void execute(IotHubStatusCode status, Object context) {
        LOG.info("IoT Hub responded to device twin operation");
    }
}
