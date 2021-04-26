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
import org.onlab.packet.IPv4;
import org.onlab.packet.ARP;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRule.FlowRemoveReason;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Path;
import org.onosproject.net.topology.PathService;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.Link;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;
import java.util.Set;
import java.util.List;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
    property = {
    })
public class IpSpoofedProtection {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

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

    private final Logger log = LoggerFactory.getLogger(getClass());

    private LocalHostListener hostListener = new LocalHostListener();

    private final int ipv4_ban_priority = 10;
    private final int ipv4_intercept_priority = 15;

    /**
     * Temporary setting for intergration with upnpigd service.
     * However, this kind of settings should be done with onos-cfg or osgi-property.
     */
    private final DeviceId igd_device_id = DeviceId.deviceId("of:000012bf6e85b74f");
    private final String igd_ext_iface_name = "wan1";
    private PortNumber igd_ext_port;

    @Activate
    protected void activate() {
        log.info("Activateing...");
        appId = coreService.registerApplication("nthu.wcislab.ipspoofedprotection");

        init();
        hostService.addListener(hostListener);
        requestIntercepts();
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
        hostService.removeListener(hostListener);
        log.info("Stopped");
    }

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * 1. Find the igd public interface. (temporary)
     * 2. Allow traffic with known host ip.
     * 3. Drop all IPv4 packets initially.
     */
    void init() {
        // 1. Find the igd public interface. (temporary)
        List<Port> port_list = deviceService.getPorts(igd_device_id);

        for (Port port : port_list) {
            if (port.annotations().value("portName").equals(igd_ext_iface_name)) {
                igd_ext_port = port.number();
                log.info("External IGD port detected:\n{}", port.toString());
                break;
            }
        }

        if (igd_ext_port == null) {
            log.error("External IGD port with name {} is not found." +
             "Please check your network topology and then restart the app", igd_ext_iface_name);
        }

        // 2. Allow traffic with known host ip.
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4);
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER);

        for (Host host : hostService.getHosts()) {
            HostLocation hloc = host.location();
            if (hloc.equals(new ConnectPoint(igd_device_id, igd_ext_port))) {
                continue;
            }

            for (IpAddress ip : host.ipAddresses()) {
                selector.matchIPSrc(IpPrefix.valueOf(ip, Ip4Address.INET_BIT_LENGTH));
                writeFlowRule(hloc.deviceId(), selector, treatment, ipv4_intercept_priority, 0);
            }
        }

        // 3. Drop all IPv4 packets initially.
        selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4);

        treatment = DefaultTrafficTreatment.builder()
            .drop();

        Iterable<Device> devices = deviceService.getAvailableDevices();
        for (Device device : devices) {
            writeFlowRule(device.id(), selector, treatment, ipv4_ban_priority, 0);
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

    private class LocalHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            Host host = event.subject();

            switch (event.type()) {
                case HOST_ADDED:
                    if (isFromIGDExtPort(host.location())) {
                        return;
                    }

                    Set<IpAddress> ips = host.ipAddresses();
                    if (ips.isEmpty()) {
                        return;
                    }

                    IpAddress ip = ips.iterator().next();
                    TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(IpPrefix.valueOf(ip, Ip4Address.INET_BIT_LENGTH));

                    TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
                        .setOutput(PortNumber.CONTROLLER);

                    writeFlowRule(host.location().deviceId(), selector, treatment, ipv4_intercept_priority, 0);
                case HOST_UPDATED:
                    log.info("nothing for now");
                default:
                    log.info("nothing for now");
            }
        }

        private boolean isFromIGDExtPort(ConnectPoint cp) {
            return cp.equals(new ConnectPoint(igd_device_id, igd_ext_port));
        }
    }
}
