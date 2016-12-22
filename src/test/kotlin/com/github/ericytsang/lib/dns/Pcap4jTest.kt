package com.github.ericytsang.lib.dns

import com.github.ericytsang.lib.bytearrayextensions.eq
import org.junit.Test
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.EthernetPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.Packet
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.namednumber.EtherType
import org.pcap4j.packet.namednumber.IpNumber
import org.pcap4j.packet.namednumber.IpVersion
import org.pcap4j.packet.namednumber.UdpPort
import org.pcap4j.util.MacAddress
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeoutException
import kotlin.concurrent.thread

/**
 * Created by surpl on 10/22/2016.
 */
class Pcap4jTest
{
    fun openNic():PcapHandle
    {
        // open the network interface
        val nic = Pcaps.getDevByAddress(InetAddress.getLocalHost())
            ?: throw RuntimeException("please replace IP address with IP address of this computer on the LAN")
        return nic.openLive(0x10000,PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,10)
    }

    fun getHostWanNifs():List<NetworkInterface>
    {
        return NetworkInterface.getNetworkInterfaces().toList()
            .filter()
            {
                it.interfaceAddresses
                    .let {it?.toList() ?: emptyList()}
                    .any {it.address.isSiteLocalAddress && !it.address.isLoopbackAddress}
            }
    }

    @Test
    fun listHostWanNifs()
    {
        println("InetAddress.getLocalHost().hostAddress: ${InetAddress.getLocalHost().hostAddress}")
        println("=====================================================================")
        for (nif in getHostWanNifs())
        {
            println("display name: ${nif.displayName}")
            println("interface addresses: ${nif.interfaceAddresses?.toList()}")
            println("internet addresses: ${nif.inetAddresses?.toList()}")
            println("hardware address: ${nif.hardwareAddress?.let {MacAddress.getByAddress(it)}}")
            println("=====================================================================")
        }
    }

    @Test
    fun openNicTest()
    {
        // open the network interface then close it
        openNic().close()
    }

    @Test
    fun capturePacketTest()
    {
        // open the network interface
        val openedNic = openNic()

        // capture a packet
        while (true)
        {
            try
            {
                println(openedNic.nextPacketEx)
                break
            }
            catch (ex:TimeoutException)
            {
                // ignore....openedNic.nextPacketEx throws it all the time
            }
        }

        // close the network interface controller
        openedNic.close()
    }

    @Test
    fun resolveWanAddress()
    {
        val udpPayload = Math.random().toString().toByteArray()

        // open all nics
        val openNics = Pcaps.findAllDevs().map()
        {
            nic ->
            nic!!.openLive(0x10000,PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,10)
        }

        var packetToWan:Packet? = null
        val unblockedOnPacketSet = CountDownLatch(1)

        // listen for udp packets on all NICs
        openNics.forEach()
        {
            openNic ->

            thread()
            {
                // loop to decode packets from the nic
                try
                {
                    openNic.loop(-1)
                    {
                        capturedPacket:Packet ->

                        // get the udp packet
                        val udpPacket = capturedPacket.get(UdpPacket::class.java)
                            ?: return@loop

                        // if it's the packet we're looking for, maintain a
                        // reference to the packet and unblock the latch to end
                        // capturing of packets on all nics.
                        println("${udpPacket.payload.rawData} == ${udpPayload}")
                        if (udpPacket.payload.rawData eq udpPayload)
                        {
                            packetToWan = capturedPacket
                            unblockedOnPacketSet.countDown()
                        }
                    }
                }

                // this exception is expected when breakLoop is called
                catch (ex:InterruptedException)
                {
                    // breakLoop was called
                }
            }
        }

        // continuously sends udp packets until interrupted
        val sendThread = thread()
        {
            val udpSock = DatagramSocket()
            try
            {
                udpSock.connect(InetAddress.getByName("8.8.8.8"),0)
                val datagram = DatagramPacket(udpPayload,udpPayload.size)
                while (true)
                {
                    udpSock.send(datagram)
                    Thread.sleep(100)
                }
            }
            catch (ex:InterruptedException)
            {
                // expected exception thrown when interrupting sleep
            }
            finally
            {
                udpSock.close()
            }
        }

        // wait for someone to find the packet
        unblockedOnPacketSet.await()
        packetToWan!!
        openNics.forEach {it.breakLoop()}
        openNics.forEach {it.close()}
        sendThread.interrupt()
        println(packetToWan)
    }

    @Test
    fun sendPacketTest1()
    {
        // open the network interface
        val openedNic = openNic()

        NetworkInterface.getNetworkInterfaces()

        // send a packet
        val wanNif = getHostWanNifs().first()
        val localLinkAddress = MacAddress.getByAddress(wanNif.hardwareAddress)
        val gatewayLinkAddress = MacAddress.getByName("4c:8b:30:19:1e:e0")
        val localInetAddress = wanNif.inetAddresses?.toList().let {it ?: emptyList()}.find {it is Inet4Address}!! as Inet4Address
        val googleInetAddress = InetAddress.getByName("8.8.8.8") as Inet4Address
        val udpPayloadBuilder = UnknownPacket.Builder().rawData("do not be alarmed .... I'm playing with pcap4j".toByteArray())
        val udpPacketBuilder = UdpPacket.Builder()
            .payloadBuilder(udpPayloadBuilder)
            .correctLengthAtBuild(true)
            .correctChecksumAtBuild(true)
            .srcPort(UdpPort(30,"custom"))
            .dstPort(UdpPort(30,"custom"))
            .dstAddr(googleInetAddress)
            .srcAddr(localInetAddress)
        val ipPacketBuilder = IpV4Packet.Builder()
            .payloadBuilder(udpPacketBuilder)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .paddingAtBuild(true)
            .ttl(64)
            .dontFragmentFlag(true)
            .moreFragmentFlag(false)
            .dontFragmentFlag(false)
            .dstAddr(googleInetAddress)
            .protocol(IpNumber.UDP)
            .srcAddr(localInetAddress)
            .identification((Long.MAX_VALUE*Math.random()).toShort())
            .reservedFlag(false)
            .tos(IpV4Packet.IpV4Tos({4}))
            .version(IpVersion.IPV4)
        val macPacketLayer = EthernetPacket.Builder()
            .payloadBuilder(ipPacketBuilder)
            .paddingAtBuild(true)
            .srcAddr(localLinkAddress)
            .dstAddr(gatewayLinkAddress)
            .type(EtherType.IPV4)
        openedNic.sendPacket(macPacketLayer.build())

        // close the network interface controller
        openedNic.close()
    }

    @Test
    fun sendPacketTest2()
    {
        // open the network interface
        val openedNic = openNic()

        NetworkInterface.getNetworkInterfaces()

        // send a packet
        val wanNif = getHostWanNifs().first()
        val localInetAddress = wanNif.inetAddresses?.toList().let {it ?: emptyList()}.find {it is Inet4Address}!! as Inet4Address
        val googleInetAddress = InetAddress.getByName("8.8.8.8") as Inet4Address
        val udpPayloadBuilder = UnknownPacket.Builder().rawData("do not be alarmed .... I'm playing with pcap4j".toByteArray())
        val udpPacketBuilder = UdpPacket.Builder()
            .payloadBuilder(udpPayloadBuilder)
            .correctLengthAtBuild(true)
            .correctChecksumAtBuild(true)
            .srcPort(UdpPort(30,"custom"))
            .dstPort(UdpPort(30,"custom"))
            .dstAddr(googleInetAddress)
            .srcAddr(localInetAddress)
        openedNic.sendPacket(udpPacketBuilder.build())

        // close the network interface controller
        openedNic.close()
    }
}
