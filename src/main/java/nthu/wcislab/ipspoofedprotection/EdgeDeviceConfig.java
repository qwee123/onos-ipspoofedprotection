package nthu.wcislab.ipspoofedprotection;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;

import java.util.List;
import java.util.HashSet;

public class EdgeDeviceConfig extends Config<ApplicationId> {
    private static final String EDGE_DEVICES = "edgeDevices";

    @Override
    public boolean isValid() {
        return hasOnlyFields(EDGE_DEVICES);
    }

    public HashSet<DeviceId> edgeDevices() {
        List<DeviceId> devices = getList(EDGE_DEVICES, i -> {
            return DeviceId.deviceId(i);
        }, null);

        return new HashSet<DeviceId>(devices);
    }
}
