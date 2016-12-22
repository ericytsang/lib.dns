package com.github.ericytsang.lib.dns

import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket

class TcpDnsTest
{
    @Test
    fun test()
    {
        // craft dns query
        val dnsQuery = DnsPacket.Builder()
            .transactionId(40)
            .isNonAuthenticatedDataAcceptable(false)
            .isRecursive(true)
            .isResponse(false)
            .replyCode(DnsPacket.ReplyCode.OK)
            .questions(listOf(Question("www.youtube.com",1,1)))
            .answers(emptyList())
            .authorities(emptyList())
            .additionals(emptyList())
            .build().rawData

        // connect to dns server
        val sock = Socket("8.8.8.8",53)

        // send queries
        run {
            // send a length before sending the dns packet
            sock.outputStream.let(::DataOutputStream).writeShort(dnsQuery.size)
            sock.outputStream.write(dnsQuery)
        }
        run {
            // send a length before sending the dns packet
            sock.outputStream.let(::DataOutputStream).writeShort(dnsQuery.size)
            sock.outputStream.write(dnsQuery)
        }
        sock.shutdownOutput()

        // read responses
        run {
            // receive a length before receiving the dns packet
            val len = sock.inputStream.let(::DataInputStream).readShort()
            val dnsResponse = ByteArray(len.toInt())
            sock.inputStream.let(::DataInputStream).readFully(dnsResponse)
            println(DnsPacket(dnsResponse))
        }
        run {
            // receive a length before receiving the dns packet
            val len = sock.inputStream.let(::DataInputStream).readShort()
            val dnsResponse = ByteArray(len.toInt())
            sock.inputStream.let(::DataInputStream).readFully(dnsResponse)
            println(DnsPacket(dnsResponse))
        }
        sock.shutdownInput()

        // done done
        sock.close()
    }
}
