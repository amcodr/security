package com.amazon.opendistroforelasticsearch.security.support;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


// for resolving the error of getAsList method as this method is not present in ES 5.4.3
public class Setting6 {

    public static List<String> getAsList(Settings settings, String key) throws SettingsException {
        return getAsList(settings,key, Collections.emptyList());
    }

    public static List<String> getAsList(Settings settings, String key, List<String> defaultValue) throws SettingsException {
        return getAsList(settings,key, defaultValue, true);
    }

    @SuppressWarnings("unchecked")
    public static List<String> getAsList(Settings settings,String key,List<String> defaultValue,Boolean commaDelimited) throws SettingsException {
        List<String> result = new ArrayList<>();
        final Object valueFromPrefix = settings.get(key);
        if (valueFromPrefix != null) {
            if (valueFromPrefix instanceof List) {
                return Collections.unmodifiableList((List<String>) valueFromPrefix);
            } else if (commaDelimited) {
                String[] strings = Strings.splitStringByCommaToArray(settings.get(key));
                if (strings.length > 0) {
                    for (String string : strings) {
                        result.add(string.trim());
                    }
                }
            } else {
                result.add(settings.get(key).trim());
            }
        }

        if (result.isEmpty()) {
            return defaultValue;
        }
        return Collections.unmodifiableList(result);
    }
}


// related codes present in ES 6
//    /**
//     * The values associated with a setting key as an immutable list.
//     * <p>
//     * It will also automatically load a comma separated list under the settingPrefix and merge with
//     * the numbered format.
//     *
//     * @param key The setting key to load the list by
//     * @return The setting list values
//     */
//    public List<String> getAsList(String key) throws SettingsException {
//        return getAsList(key, Collections.emptyList());
//    }
//
//    /**
//     * The values associated with a setting key as an immutable list.
//     * <p>
//     * If commaDelimited is true, it will automatically load a comma separated list under the settingPrefix and merge with
//     * the numbered format.
//     *
//     * @param key The setting key to load the list by
//     * @return The setting list values
//     */
//    public List<String> getAsList(String key, List<String> defaultValue) throws SettingsException {
//        return getAsList(key, defaultValue, true);
//    }
//
//    /**
//     * The values associated with a setting key as an immutable list.
//     * <p>
//     * It will also automatically load a comma separated list under the settingPrefix and merge with
//     * the numbered format.
//     *
//     * @param key  The setting key to load the list by
//     * @param defaultValue   The default value to use if no value is specified
//     * @param commaDelimited Whether to try to parse a string as a comma-delimited value
//     * @return The setting list values
//     */
//    public List<String> getAsList(String key, List<String> defaultValue, Boolean commaDelimited) throws SettingsException {
//        List<String> result = new ArrayList<>();
//        final Object valueFromPrefix = settings.get(key);
//        if (valueFromPrefix != null) {
//            if (valueFromPrefix instanceof List) {
//                return Collections.unmodifiableList((List<String>) valueFromPrefix);
//            } else if (commaDelimited) {
//                String[] strings = Strings.splitStringByCommaToArray(get(key));
//                if (strings.length > 0) {
//                    for (String string : strings) {
//                        result.add(string.trim());
//                    }
//                }
//            } else {
//                result.add(get(key).trim());
//            }
//        }
//
//        if (result.isEmpty()) {
//            return defaultValue;
//        }
//        return Collections.unmodifiableList(result);
//    }
