package com.github.ericytsang.lib.dns

import java.nio.ByteBuffer

data class Question(val url:String,val type:Int,val classification:Int)
{
    val rawDataLen = url.length+6
    val rawData:ByteArray get() = ByteBuffer.allocate(rawDataLen)
        .apply()
        {
            // length of substring - 1 byte
            put(ResourceRecord.toLabel(url))

            // type - 2 bytes
            putShort(type.toShort())

            // class - 2 bytes
            putShort(classification.toShort())
        }
        .array()
}
