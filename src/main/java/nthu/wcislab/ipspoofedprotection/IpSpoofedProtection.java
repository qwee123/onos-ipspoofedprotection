/*
 * Copyright 2021-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nthu.wcislab.ipspoofedprotection;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.packet.PacketService;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.HashSet;
import java.util.List;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
    property = {
    })
public class IpSpoofedProtection {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private ApplicationId appId;

    private final EdgeDeviceConfigListener edgeCfgListener = new EdgeDeviceConfigListener();
    private final ConfigFactory<ApplicationId, EdgeDeviceConfig> edgeCfgFactory =
                new ConfigFactory<ApplicationId, EdgeDeviceConfig>(
                    APP_SUBJECT_FACTORY, EdgeDeviceConfig.class, "EdgeDeviceConfig") {
                    @Override
                    public EdgeDeviceConfig createConfig() {
                        return new EdgeDeviceConfig();
                    }
                };

    private final Logger log = LoggerFactory.getLogger(getClass());

    private LocalHostListener hostListener = new LocalHostListener();

    private Set<DeviceId> edgeDevices = new HashSet<DeviceId>();

    private final int ipv4_ban_priority = 10;
    private final int ipv4_intercept_priority = 15;
    private final TrafficSelector.Builder ban_selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4);
    private final TrafficTreatment.Builder ban_treatment = DefaultTrafficTreatment.builder()
                .drop();

    /**
     * Temporary setting for intergration with upnpigd service.
     * However, this kind of settings should be done with onos-cfg or osgi-property.
     */
    private final DeviceId igd_device_id = DeviceId.deviceId("of:000012bf6e85b74f");
    private final String igd_ext_iface_name = "wan1";
    private PortNumber igd_ext_port;
    private ConnectPoint igd_ext_cp;

    @Activate
    protected void activate() {
        log.info("Activateing...");
        appId = coreService.registerApplication("nthu.wcislab.ipspoofedprotection");

        cfgService.addListener(edgeCfgListener);
        cfgService.registerConfigFactory(edgeCfgFactory);
        hostService.addListener(hostListener);
        init();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        hostService.removeListener(hostListener);
        cfgService.unregisterConfigFactory(edgeCfgFactory);
        cfgService.removeListener(edgeCfgListener);
        log.info("Stopped");
    }

    /**
     * 1. Find the igd public interface. (temporary)
     * 2. Allow traffic with known host ip.
     * 3. Drop all IPv4 packets on edge devices. All devices are edge devices in default.
     */
    void init() {
        // 1. Find the igd public interface. (temporary)
        List<Port> port_list = deviceService.getPorts(igd_device_id);

        for (Port port : port_list) {
            if (port.annotations().value("portName").equals(igd_ext_iface_name)) {
                igd_ext_port = port.number();
                log.info("External IGD port detected:\n{}", port.toString());
                igd_ext_cp = new ConnectPoint(igd_device_id, igd_ext_port);
                break;
            }
        }

        if (igd_ext_port == null) {
            log.error("External IGD port with name {} is not found." +
             "Please check your network topology and then restart the app", igd_ext_iface_name);
        }

        // 2. Drop all IPv4 packets on edge devices.
        // 3. Only allow traffic with known host,
        // 4. plus traffic from other network devices.
        Iterable<Device> devices = deviceService.getAvailableDevices();
        for (Device device : devices) {
            DeviceId deviceId = device.id();
            edgeDevices.add(deviceId);
            writeFlowRule(deviceId, ban_selector, ban_treatment, ipv4_ban_priority, 0);
            allowKnownHost(deviceId);
            allowInfraTraffic(deviceId);
        }
    }

    public void allowInfraTraffic(DeviceId deviceId) {
        List<Port> ports = deviceService.getPorts(deviceId);

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4);
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER);

        for (Port port : ports) {
            PortNumber pn = port.number();
            if (pn.isLogical()) {
                continue;
            }

            ConnectPoint cp = new ConnectPoint(deviceId, pn);
            if (!edgePortService.isEdgePoint(cp)) {
                selector.matchInPort(port.number());
                writeFlowRule(deviceId, selector, treatment, ipv4_intercept_priority, 0);
            }
        }
    }

    public void allowKnownHost(DeviceId deviceId) {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4);
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER);


        for (Host host : hostService.getConnectedHosts(deviceId)) {
            HostLocation hloc = host.location();
            if (hloc.equals(igd_ext_cp)) {
                continue;
            }

            selector.matchInPort(hloc.port());
            for (IpAddress ip : host.ipAddresses()) {
                selector.matchIPSrc(IpPrefix.valueOf(ip, Ip4Address.INET_BIT_LENGTH));
                writeFlowRule(deviceId, selector, treatment, ipv4_intercept_priority, 0);
            }
        }
    }

    public void writeFlowRule(DeviceId deviceId, TrafficSelector.Builder selector,
                        TrafficTreatment.Builder treatment, int priority, int timeout) {
        FlowRule.Builder rule_builder = DefaultFlowRule.builder()
            .withSelector(selector.build())
            .withTreatment(treatment.build())
            .withPriority(priority)
            .forDevice(deviceId)
            .fromApp(appId);

        if (timeout == 0) {
            rule_builder.makePermanent();
        } else {
            rule_builder.makeTemporary(timeout);
        }

        flowRuleService.applyFlowRules(rule_builder.build());
    }

    public void removeFlowRule(DeviceId deviceId, TrafficSelector.Builder selector,
                        TrafficTreatment.Builder treatment, int priority) {
        FlowRule.Builder rule_builder = DefaultFlowRule.builder()
            .withSelector(selector.build())
            .withTreatment(treatment.build())
            .makeTemporary(0)
            .withPriority(priority)
            .forDevice(deviceId)
            .fromApp(appId);

        flowRuleService.removeFlowRules(rule_builder.build());
    }

    public void removeAppFlowRules(DeviceId deviceId) {
        for (FlowEntry entry : flowRuleService.getFlowEntries(deviceId)) {
            if (entry.appId() != appId.id()) {
                continue;
            }

            flowRuleService.removeFlowRules(entry);
        }
    }

    private class LocalHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            Host host = event.subject();
            HostLocation hloc = host.location();

            if (!edgeDevices.contains(hloc.deviceId()) || hloc.equals(igd_ext_cp)) {
                return;
            }

            Set<IpAddress> current_ip = host.ipAddresses();
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4);
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.CONTROLLER);

            switch (event.type()) {
                case HOST_ADDED:
                    if (current_ip.isEmpty()) {
                        return;
                    }

                    selector.matchIPSrc(IpPrefix.valueOf(current_ip.iterator().next(), Ip4Address.INET_BIT_LENGTH));
                    writeFlowRule(hloc.deviceId(), selector, treatment, ipv4_intercept_priority, 0);
                    break;
                case HOST_UPDATED:
                    //Not sure if a null pointer check of prevSubject() is needed.
                    //I mean, HOST_UPDATED means there was a host subject before, and now it's updated.
                    //So, I guess, HOST_UPDATED means prevSubject definitely exist?
                    Set<IpAddress> prev_ip = event.prevSubject().ipAddresses();

                    for (IpAddress ip : prev_ip) {
                        if (!current_ip.contains(ip)) {
                            selector.matchIPSrc(IpPrefix.valueOf(ip, Ip4Address.INET_BIT_LENGTH));
                            removeFlowRule(hloc.deviceId(), selector, treatment, ipv4_intercept_priority);
                        }
                    }

                    for (IpAddress ip : current_ip) {
                        if (!prev_ip.contains(ip)) {
                            selector.matchIPSrc(IpPrefix.valueOf(ip, Ip4Address.INET_BIT_LENGTH));
                            writeFlowRule(hloc.deviceId(), selector, treatment, ipv4_intercept_priority, 0);
                        }
                    }
                    break;
                case HOST_REMOVED:
                    for (IpAddress ip : current_ip) {
                        selector.matchIPSrc(IpPrefix.valueOf(ip, Ip4Address.INET_BIT_LENGTH));
                        removeFlowRule(hloc.deviceId(), selector, treatment, ipv4_intercept_priority);
                    }
                    break;
                default:
                    log.warn("Unhandled Host Event: {}", event.toString());
                    break;
            }
        }
    }

    private class EdgeDeviceConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                            && event.configClass().equals(EdgeDeviceConfig.class)) {

                EdgeDeviceConfig config = cfgService.getConfig(appId, EdgeDeviceConfig.class);
                if (config != null) {
                    HashSet<DeviceId> newDevices = config.edgeDevices();

                    for (DeviceId deviceId : edgeDevices) {
                        if (!newDevices.contains(deviceId)) {
                            removeAppFlowRules(deviceId);
                        }
                    }

                    for (DeviceId deviceId : newDevices) {
                        if (!edgeDevices.contains(deviceId) && deviceService.isAvailable(deviceId)) {
                            writeFlowRule(deviceId, ban_selector, ban_treatment, ipv4_ban_priority, 0);
                            allowKnownHost(deviceId);
                            allowInfraTraffic(deviceId);
                        }
                    }
                    log.info("Original edge devices: {}\n Updated edge devices: {}",
                                            edgeDevices.toString(), newDevices.toString());
                    edgeDevices = newDevices;
                }
            }
      }
    }
}
