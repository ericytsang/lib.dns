package com.github.ericytsang.lib.dns

import com.github.ericytsang.lib.bytearrayextensions.getInt
import com.github.ericytsang.lib.bytearrayextensions.getLong
import java.nio.ByteBuffer
import java.nio.charset.Charset

data class ResourceRecord(val url:String,val type:Int,val classification:Int,val ttl:Long,val data:ByteArray)
{
    companion object
    {
        fun parse(data:ByteArray,start:Int):Result<ResourceRecord>
        {
            var cursor = start
            val (newPos,url) = parseLabelOrPointer(data,cursor)
            cursor = newPos
            val type = data.getInt(cursor*8,2*8)
            cursor += 2
            val classification = data.getInt(cursor*8,2*8)
            cursor += 2
            val ttl = data.getLong(cursor*8,4*8)
            cursor += 4
            val datalen = data.getInt(cursor*8,2*8)
            cursor += 2

            val parsed = when (type)
            {
            // NS, CNAME or PTR
                2,5,12 ->
                {
                    val rdata = parseLabelOrPointer(data,cursor)
                    cursor = rdata.cursorPos
                    ResourceRecord(url,type,classification,ttl,toLabel(rdata.parsed))
                }
            // SOA
                6 ->
                {
                    var rdata = byteArrayOf()
                    rdata += parseLabelOrPointer(data,cursor)
                        .let {cursor = it.cursorPos;toLabel(it.parsed)}
                    rdata += parseLabelOrPointer(data,cursor)
                        .let {cursor = it.cursorPos;toLabel(it.parsed)}
                    rdata += data.sliceArray(cursor..cursor+20-1)
                    cursor += 20
                    ResourceRecord(url,type,classification,ttl,rdata)
                }
            // MX
                15 ->
                {
                    var rdata = byteArrayOf()
                    rdata += data.sliceArray(cursor..cursor+2-1)
                    cursor += 2
                    rdata += parseLabelOrPointer(data,cursor)
                        .let {cursor = it.cursorPos;toLabel(it.parsed)}
                    ResourceRecord(url,type,classification,ttl,rdata)
                }
            // some type that doesn't have pointers or labels...no need to convert pointers to labels
                else ->
                {
                    val rdata = data.sliceArray(cursor..cursor+datalen-1)
                    cursor += datalen
                    ResourceRecord(url,type,classification,ttl,rdata)
                }
            }

            return Result(cursor,parsed)
        }

        fun toLabel(url:String):ByteArray
        {
            val buffer = ByteBuffer.allocate(url.length+2)
            url.split('.').forEach()
            {
                substring ->
                buffer.put(substring.length.toByte())
                buffer.put(substring.toByteArray())
            }
            buffer.put(0x00)
            return buffer.array()
        }

        private fun parseLabelOrPointer(data:ByteArray,start:Int):Result<String>
        {
            var cursor = start
            val url = when (data.getInt(cursor*8,2))
            {
            // when the next 2 bits are 0b00, parse as label
                0b00 ->
                {
                    val strlen = data.getInt(cursor*8,1*8)
                    val string = String(data,cursor+1,strlen,Charset.defaultCharset())
                    cursor += strlen+1
                    if (strlen != 0)
                    {
                        val nextString = parseLabelOrPointer(data,cursor)
                        cursor = nextString.cursorPos
                        if (nextString.parsed != "")
                        {
                            string+'.'+nextString.parsed
                        }
                        else
                        {
                            string
                        }
                    }
                    else
                    {
                        ""
                    }
                }
            // when the next 2 bits are 0b11, parse as pointer
                0b11 ->
                {
                    val result = parseLabelOrPointer(data,data.getInt(cursor*8+2,14))
                    cursor += 2
                    result.parsed
                }
                else -> throw RuntimeException("unhandled case")
            }
            return Result(cursor,url)
        }

        data class Result<out T>(val cursorPos:Int,val parsed:T)
    }

    val rawDataLen = url.length+12+data.size
    val rawData:ByteArray get() = ByteBuffer.allocate(rawDataLen)
        .apply()
        {
            // name - url.length+2 bytes
            put(toLabel(url))

            // type - 2 bytes
            putShort(type.toShort())

            // class - 2 bytes
            putShort(classification.toShort())

            // ttl - 4 bytes
            putInt(ttl.toInt())

            // data length - 2 bytes
            putShort(data.size.toShort())

            // data - data length bytes
            put(data)
        }
        .array()
}
