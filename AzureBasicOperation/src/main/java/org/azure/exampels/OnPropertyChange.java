package org.azure.exampels;

import com.microsoft.azure.sdk.iot.device.DeviceTwin.Property;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.TwinPropertyCallBack;

public class OnPropertyChange implements TwinPropertyCallBack {

    @Override
    public void TwinPropertyCallBack(Property property, Object context) {
        //Nothing to do here
    }
}
