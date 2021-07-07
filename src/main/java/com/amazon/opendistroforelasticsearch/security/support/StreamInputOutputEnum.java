package com.amazon.opendistroforelasticsearch.security.support;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;

public class StreamInputOutputEnum {

    /**
     * Reads an enum with type E that was serialized based on the value of it's ordinal
     */
//    for handling the readEnum function in ES5.4
    public static <E extends Enum<E>> E readEnum(StreamInput in,Class<E> enumClass) throws IOException{
        int ordinal = in.readInt();
        E[] values = enumClass.getEnumConstants();
        if(ordinal < 0 || ordinal >= values.length){
            throw new IOException("Unknown " + enumClass.getSimpleName() + " ordinal [" + ordinal + "]");
        }
        return values[ordinal];
    }



    /**
     * Writes an enum with type E that by serialized it based on it's ordinal value
     */
//    handling write Enum functionality in ES5.4

    public static <E extends Enum<E>> void writeEnum(StreamOutput out,E enumValue) throws IOException {
        out.writeVInt(enumValue.ordinal());
    }



}
