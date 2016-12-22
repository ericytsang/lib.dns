package com.github.ericytsang.lib.dns

import com.github.ericytsang.lib.bytearrayextensions.getFlag
import com.github.ericytsang.lib.bytearrayextensions.getInt
import org.pcap4j.packet.AbstractPacket
import org.pcap4j.packet.namednumber.NamedNumber
import java.nio.ByteBuffer
import java.nio.charset.Charset

/**
 * interface for accessing and manipulating the bytes of a DNS packet.
 */
class DnsPacket(_data_:ByteArray):AbstractPacket()
{
    private val header = Header(_data_)

    override fun getHeader():Header
    {
        return header
    }

    override fun getBuilder():Builder
    {
        return Builder(this)
    }

    class Header(private val _data_:ByteArray):AbstractHeader()
    {
        override fun getRawFields():MutableList<ByteArray>
        {
            return mutableListOf(_data_)
        }

        /**
         * 2 bytes
         */
        val transactionId:Int
            get() = _data_.getInt(0,2*8)

        /**
         * 1 bit
         */
        val isResponseFlag:Boolean
            get() = _data_.getFlag(2,0x80)

        /**
         * 1 bit
         */
        val isAuthoritativeFlag:Boolean
            get() = _data_.getFlag(2,0x04)

        /**
         * 1 bit
         */
        val isTruncatedFlag:Boolean
            get() = _data_.getFlag(2,0x02)

        /**
         * 1 bit
         */
        val isRecursiveFlag:Boolean
            get() = _data_.getFlag(2,0x01)

        /**
         * 1 bit
         */
        val isRecursionAvailableFlag:Boolean
            get() = _data_.getFlag(3,0x80)

        /**
         * 1 bit
         */
        val isAnswerAuthenticatedFlag:Boolean
            get() = _data_.getFlag(3,0x20)

        /**
         * 1 bit
         */
        val isNonAuthenticatedDataAcceptableFlag:Boolean
            get() = _data_.getFlag(3,0x10)

        /**
         * 4 bits
         */
        val replyCode:ReplyCode
            get() = ReplyCode.fromInt(_data_.getInt(7*4,4))

        /**
         * 2 bytes
         */
        val questionCount:Int
            get() = _data_.getInt(4*8,2*8)

        /**
         * 2 bytes
         */
        val answerCount:Int
            get() = _data_.getInt(6*8,2*8)

        /**
         * 2 bytes
         */
        val authorityCount:Int
            get() = _data_.getInt(8*8,2*8)

        /**
         * 2 bytes
         */
        val additionalCount:Int
            get() = _data_.getInt(10*8,2*8)

        var cursor = 12

        /**
         * questions
         */
        val questions:List<Question> = run()
        {
            (1..questionCount).map()
            {
                val strings = mutableListOf<String>()
                do
                {
                    val strlen = _data_.getInt(cursor*8,1*8)
                    strings += String(_data_,cursor+1,strlen,Charset.defaultCharset())
                    cursor += strlen+1
                }
                while (strlen > 0)
                val url = strings.dropLast(1).joinToString("")
                val type = _data_.getInt(cursor*8,2*8)
                cursor += 2
                val classification = _data_.getInt(cursor*8,2*8)
                cursor += 2
                Question(url,type,classification)
            }
        }

        /**
         * answers
         */
        val answers:List<ResourceRecord> = run()
        {
            (1..answerCount).map()
            {
                val r = ResourceRecord.parse(_data_,cursor)
                cursor = r.cursorPos
                r.parsed
            }
        }

        val authorities:List<ResourceRecord> = run()
        {
            (1..authorityCount).map()
            {
                val r = ResourceRecord.parse(_data_,cursor)
                cursor = r.cursorPos
                r.parsed
            }
        }

        val additionals:List<ResourceRecord> = run()
        {
            (1..additionalCount).map()
            {
                val r = ResourceRecord.parse(_data_,cursor)
                cursor = r.cursorPos
                r.parsed
            }
        }
    }

    override fun toString():String
    {
        return "" +
        "[DNS Packet]\n" +
        "    transactionId: ${header.transactionId}\n" +
        "    isResponseFlag: ${header.isResponseFlag}\n" +
        "    isAuthoritativeFlag: ${header.isAuthoritativeFlag}\n" +
        "    isTruncatedFlag: ${header.isTruncatedFlag}\n" +
        "    isRecursiveFlag: ${header.isRecursiveFlag}\n" +
        "    isRecursionAvailableFlag: ${header.isRecursionAvailableFlag}\n" +
        "    isAnswerAuthenticatedFlag: ${header.isAnswerAuthenticatedFlag}\n" +
        "    isNonAuthenticatedDataAcceptableFlag: ${header.isNonAuthenticatedDataAcceptableFlag}\n" +
        "    replyCode: ${header.replyCode}\n" +
        "    questionCount: ${header.questionCount}\n" +
        "    answerCount: ${header.answerCount}\n" +
        "    authorityCount: ${header.authorityCount}\n" +
        "    additionalCount: ${header.additionalCount}\n" +
        "    questions: ${header.questions}\n" +
        "    answers: ${header.answers}\n" +
        "    authorities: ${header.authorities}\n" +
        "    additionals: ${header.additionals}"
    }

    class Builder(packet:DnsPacket? = null):AbstractBuilder()
    {
        var transactionId:Int = packet?.getHeader()?.transactionId ?: 0
        var isResponse:Boolean = packet?.getHeader()?.isResponseFlag ?: false
        var isRecursive:Boolean = packet?.getHeader()?.isRecursiveFlag ?: true
        var isNonAuthenticatedDataAcceptable:Boolean = packet?.getHeader()?.isNonAuthenticatedDataAcceptableFlag ?: false
        var replyCode:ReplyCode = packet?.getHeader()?.replyCode ?: ReplyCode.OK
        var questions:List<Question> = packet?.getHeader()?.questions ?: emptyList()
        var answers:List<ResourceRecord> = packet?.getHeader()?.answers ?: emptyList()
        var authorities:List<ResourceRecord> = packet?.getHeader()?.authorities ?: emptyList()
        var additionals:List<ResourceRecord> = packet?.getHeader()?.additionals ?: emptyList()

        /**
         * transaction id of the DNS packet.
         *
         * @type {Short}
         */
        fun transactionId(value:Int):Builder
        {
            transactionId = value
            return this
        }

        /**
         * indicates if DNS packet is a DNS reply or not.
         *
         * @type {Boolean}
         */
        fun isResponse(value:Boolean):Builder
        {
            isResponse = value
            return this
        }

        /**
         * indicates if the DNS query is to be done recursively or not.
         *
         * @type {Boolean}
         */
        fun isRecursive(value:Boolean):Builder
        {
            isRecursive = value
            return this
        }

        /**
         * indicates if non-authenticated data in the answer is acceptable.
         *
         * @type {Boolean}
         */
        fun isNonAuthenticatedDataAcceptable(value:Boolean):Builder
        {
            isNonAuthenticatedDataAcceptable = value
            return this
        }

        /**
         * indicates if non-authenticated data in the answer is acceptable.
         *
         * @type {Boolean}
         */
        fun replyCode(value:ReplyCode):Builder
        {
            replyCode = value
            return this
        }

        /**
         * list of questions in the form of strings to look up.
         *
         * @type {List<Question>}
         */
        fun questions(value:List<Question>):Builder
        {
            questions = value
            return this
        }

        /**
         * list of answers in the form of strings to look up.
         *
         * @type {List<Answer>}
         */
        fun answers(value:List<ResourceRecord>):Builder
        {
            answers = value
            return this
        }

        /**
         * list of answers in the form of strings to look up.
         *
         * @type {List<Answer>}
         */
        fun authorities(value:List<ResourceRecord>):Builder
        {
            authorities = value
            return this
        }

        /**
         * list of answers in the form of strings to look up.
         *
         * @type {List<Answer>}
         */
        fun additionals(value:List<ResourceRecord>):Builder
        {
            additionals = value
            return this
        }

        /**
         * craft the DNS query packet.
         */
        override fun build():DnsPacket
        {
            val dnsHeader = ByteBuffer.allocate(12+
                questions.map {it.rawDataLen}.sum()+
                answers.map {it.rawDataLen}.sum()+
                authorities.map {it.rawDataLen}.sum()+
                additionals.map {it.rawDataLen}.sum())

            // transactionId - 2 bytes
            dnsHeader.putShort(transactionId.toShort())

            // flags - 2 bytes
            var flags = 0x0000
            if (isResponse)
            {
                flags = flags or 0x8000
            }
            if (isRecursive)
            {
                flags = flags or 0x0100
            }
            if (isNonAuthenticatedDataAcceptable)
            {
                flags = flags or 0x0010
            }
            if (replyCode.value() != 0)
            {
                flags = flags or (replyCode.value() and 0x000F)
            }
            dnsHeader.putShort(flags.toShort())

            // question count - 2 bytes
            dnsHeader.putShort(questions.size.toShort())

            // answer count - 2 bytes
            dnsHeader.putShort(answers.size.toShort())

            // authority count - 2 bytes
            dnsHeader.putShort(authorities.size.toShort())

            // additional count - 2 bytes
            dnsHeader.putShort(additionals.size.toShort())

            // queries
            questions.forEach {dnsHeader.put(it.rawData)}

            // answers
            answers.forEach {dnsHeader.put(it.rawData)}

            // authorities
            authorities.forEach {dnsHeader.put(it.rawData)}

            // additional
            additionals.forEach {dnsHeader.put(it.rawData)}

            // return...
            return DnsPacket(dnsHeader.array())
        }
    }

    class ReplyCode private constructor(value:Int,name:String):NamedNumber<Int,ReplyCode>(value,name)
    {
        companion object
        {
            /**
             * No error condition.
             */
            val OK = ReplyCode(0,"OK")
            /**
             * Format error - The name server was unable to interpret the query.
             */
            val FMT_ERR = ReplyCode(1,"FMT_ERR")

            /**
             * Server failure - The name server was unable to process this query due to a problem with the name server.
             */
            val SVR_FAIL = ReplyCode(2,"SVR_FAIL")

            /**
             * Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
             */
            val NAME_ERR = ReplyCode(3,"NAME_ERR")

            /**
             * Not Implemented - The name server does not support the requested kind of query.
             */
            val NO_IMPL = ReplyCode(4,"NO_IMPL")

            /**
             * Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
             */
            val REFUSED = ReplyCode(5,"REFUSED")

            fun fromInt(int:Int):ReplyCode = when (int)
            {
                0 -> OK
                1 -> FMT_ERR
                2 -> SVR_FAIL
                3 -> NAME_ERR
                4 -> NO_IMPL
                5 -> REFUSED
                else -> throw IllegalArgumentException()
            }
        }

        override fun compareTo(other:ReplyCode):Int
        {
            throw UnsupportedOperationException("not implemented")
        }
    }
}