package org.opensourceway.sbom.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.lang.reflect.Type;

/**
 * AES json工具类
 *
 * @author zyx
 * @since 2021-09-01
 */
public class JsonParseUtils {
    private static final Gson GSON = new GsonBuilder().setDateFormat("yyyy-MM-dd HH-mm-ss").create();

    /**
     * 对象转json
     *
     * @param obj 转换的对象
     * @return String
     */
    public static String toJson(Object obj) {
        return GSON.toJson(obj);
    }

    /**
     * json 转
     *
     * @param json 转换的字符串
     * @param classOfT 转换的对象
     * @return fromJson
     */
    public static <T> T fromJson(String json, Class<T> classOfT) {
        return GSON.fromJson(json, classOfT);
    }

    /**
     * json转
     *
     * @param json 转换的字符串
     * @param typeOfT 标志
     * @return fromJson
     */
    public static <T> T fromJson(String json, Type typeOfT) {
        return GSON.fromJson(json, typeOfT);
    }
}
