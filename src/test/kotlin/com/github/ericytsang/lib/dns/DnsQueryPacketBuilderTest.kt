package com.github.ericytsang.lib.dns

import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Created by root on 25/09/16.
 */
class DnsQueryPacketBuilderTest
{
    @Test
    fun sendCraftedQuery1()
    {
        // craft the dns query packet
        val dnsQueryPacket = DnsPacket.Builder().let()
        {
            builder ->
            builder.transactionId = 93
            builder.questions = listOf(Question("daisy.ubuntu.com",1,1))
            builder.build().header.rawData
        }

        // open a socket
        val socket = DatagramSocket().apply()
        {
            connect(InetAddress.getByName("8.8.8.8"),53)
        }

        // send the packet
        socket.send(DatagramPacket(dnsQueryPacket,dnsQueryPacket.size))

        // close the socket
        socket.close()
    }

    @Test
    fun sendCraftedQuery2()
    {
        // craft the dns query packet
        val dnsQueryPacket = DnsPacket.Builder().let()
        {
            builder ->
            builder.transactionId = 93
            builder.questions = listOf(Question("daisy.ubuntu.com",1,1),Question("www.horriblesubs.info",1,1))
            builder.build().header.rawData
        }

        // open a socket
        val socket = DatagramSocket().apply()
        {
            connect(InetAddress.getByName("8.8.8.8"),53)
        }

        // send the packet
        socket.send(DatagramPacket(dnsQueryPacket,dnsQueryPacket.size))

        // close the socket
        socket.close()
    }
}
