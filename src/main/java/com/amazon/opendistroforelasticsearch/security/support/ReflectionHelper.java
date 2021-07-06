/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;



public class ReflectionHelper {

    protected static final Logger log = LogManager.getLogger(ReflectionHelper.class);

    private static Set<ModuleInfo> modulesLoaded = new HashSet<>();

    public static Set<ModuleInfo> getModulesLoaded() {
        return Collections.unmodifiableSet(modulesLoaded);
    }

    private static boolean advancedModulesDisabled() {
        return !advancedModulesEnabled;
    }

    public static void registerMngtRestApiHandler(final Settings settings) {

        if (advancedModulesDisabled()) {
            return;
        }
        
        if(!settings.getAsBoolean("http.enabled", true)) {
    
            try {
                final Class<?> clazz = Class.forName("com.amazon.opendistroforelasticsearch.security.dlic.rest.api.OpenDistroSecurityRestApiActions");
                //addLoadedModule(clazz);
                //no addLoadedModule(clazz) here because its not a typical module
                //and it is not loaded in every case/on every node
            } catch (final Throwable e) {
                log.warn("Unable to register Rest Management Api Module due to {}", e.toString());
                if(log.isDebugEnabled()) {
                    log.debug("Stacktrace: ",e);
                }
            }
        }
    }



    @SuppressWarnings("unchecked")
    public static <T> T instantiateAAA(final String clazz, final Settings settings, final Path configPath, final boolean checkEnterprise) {

        if (checkEnterprise && advancedModulesDisabled()) {
            throw new ElasticsearchException("Can not load '{}' because advanced modules are disabled", clazz);
        }

        try {
            final Class<?> clazz0 = Class.forName(clazz);
            final T ret = (T) clazz0.getConstructor(Settings.class, Path.class).newInstance(settings, configPath);

            addLoadedModule(clazz0);

            return ret;

        } catch (final Throwable e) {
            log.warn("Unable to enable '{}' due to {}", clazz, e.toString());
            if(log.isDebugEnabled()) {
                log.debug("Stacktrace: ",e);
            }
            throw new ElasticsearchException(e);
        }
    }


    public static boolean isAdvancedModuleAAAModule(final String clazz) {
        boolean advancedModuleInstalled = false;



        return advancedModuleInstalled;
    }

    public static boolean addLoadedModule(Class<?> clazz) {
        ModuleInfo moduleInfo = getModuleInfo(clazz);
        if (log.isDebugEnabled()) {
            log.debug("Loaded module {}", moduleInfo);
        }
        return modulesLoaded.add(moduleInfo);
    }

    private static boolean advancedModulesEnabled;

    // TODO static hack
    public static void init(final boolean advancedModulesEnabled) {
        ReflectionHelper.advancedModulesEnabled = advancedModulesEnabled;
    }

    private static ModuleInfo getModuleInfo(final Class<?> impl) {

        ModuleType moduleType = ModuleType.getByDefaultImplClass(impl);
        ModuleInfo moduleInfo = new ModuleInfo(moduleType, impl.getName());

        try {

            final String classPath = impl.getResource(impl.getSimpleName() + ".class").toString();
            moduleInfo.setClasspath(classPath);

            if (!classPath.startsWith("jar")) {
                return moduleInfo;
            }

            final String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) + "/META-INF/MANIFEST.MF";

            try (InputStream stream = new URL(manifestPath).openStream()) {
                final Manifest manifest = new Manifest(stream);
                final Attributes attr = manifest.getMainAttributes();
                moduleInfo.setVersion(attr.getValue("Implementation-Version"));
                moduleInfo.setBuildTime(attr.getValue("Build-Time"));
                moduleInfo.setGitsha1(attr.getValue("git-sha1"));
            }
        } catch (final Throwable e) {
            log.error("Unable to retrieve module info for " + impl, e);
        }

        return moduleInfo;
    }
}
