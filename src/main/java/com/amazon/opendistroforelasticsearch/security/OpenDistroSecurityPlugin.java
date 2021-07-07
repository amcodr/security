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

package com.amazon.opendistroforelasticsearch.security;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;


import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLogSslExceptionHandler;
import com.amazon.opendistroforelasticsearch.security.auth.BackendRegistry;
import com.amazon.opendistroforelasticsearch.security.auth.internal.InternalAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.http.XFFResolver;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecuritySSLPlugin;
import com.amazon.opendistroforelasticsearch.security.ssl.SslExceptionHandler;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.OpenDistroSecuritySSLNettyTransport;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.filter.OpenDistroSecurityRestFilter;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ReflectionHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.Lifecycle.State;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsFilter;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.ClusterPlugin;
import org.elasticsearch.plugins.MapperPlugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.action.search.RemoteClusterService;
import org.elasticsearch.transport.*;


import com.google.common.collect.Lists;
import org.elasticsearch.watcher.ResourceWatcherService;

public final class OpenDistroSecurityPlugin extends OpenDistroSecuritySSLPlugin implements ClusterPlugin, MapperPlugin {

    private static final String KEYWORD = ".keyword";
    private final boolean tribeNodeClient;
    private final boolean dlsFlsAvailable;
    private final Constructor<?> dlsFlsConstructor;
    private boolean sslCertReloadEnabled;
    private volatile OpenDistroSecurityRestFilter securityRestHandler;
    private volatile ThreadPool threadPool;
    private volatile IndexBaseConfigurationRepository cr;
    private volatile AdminDNs adminDns;
    private volatile ClusterService cs;
    private volatile AuditLog auditLog;
    private volatile BackendRegistry backendRegistry;
    private volatile SslExceptionHandler sslExceptionHandler;
    private volatile Client localClient;
    private final boolean disabled;
    private final boolean advancedModulesEnabled;
    private final boolean sslOnly;
    private final List<String> demoCertHashes = new ArrayList<String>(3);
    private volatile IndexResolverReplacer irr;

    @Override
    public void close() throws IOException {
        //TODO implement close
        super.close();
    }

    private final SslExceptionHandler evaluateSslExceptionHandler() {
        if (client || tribeNodeClient || disabled || sslOnly) {
            return new SslExceptionHandler(){};
        }

        return Objects.requireNonNull(sslExceptionHandler);
    }

    private static boolean isDisabled(final Settings settings) {
        return settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_DISABLED, false);
    }

    private static boolean isSslOnlyMode(final Settings settings) {
        return settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, false);
    }

    /**
     * SSL Cert Reload will be enabled only if security is not disabled and not in we are not using sslOnly mode.
     * @param settings Elastic configuration settings
     * @return true if ssl cert reload is enabled else false
     */
    private static boolean isSslCertReloadEnabled(final Settings settings) {
        return settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD_ENABLED, false);
    }

//    as the ES 5 does not accept the path in plugin constructor hence creating a new constructor


    public OpenDistroSecurityPlugin(final Settings settings) {

        super(settings, new Environment(settings).configFile(), isDisabled(settings));

        disabled = isDisabled(settings);
        sslCertReloadEnabled = isSslCertReloadEnabled(settings);

        if(disabled) {
            this.tribeNodeClient = false;
            this.dlsFlsAvailable = false;
            this.dlsFlsConstructor = null;
            this.advancedModulesEnabled = false;
            this.sslOnly = false;
            this.sslCertReloadEnabled = false;
            log.warn("Open Distro Security plugin installed but disabled. This can expose your configuration (including passwords) to the public.");
            return;
        }

        sslOnly = isSslOnlyMode(settings);
        if(sslOnly) {
            this.tribeNodeClient = false;
            this.dlsFlsAvailable = false;
            this.dlsFlsConstructor = null;
            this.advancedModulesEnabled = false;
            this.sslCertReloadEnabled = false;
            log.warn("Open Distro Security plugin run in ssl only mode. No authentication or authorization is performed");
            return;
        }


        demoCertHashes.add("54a92508de7a39d06242a0ffbf59414d7eb478633c719e6af03938daf6de8a1a");
        demoCertHashes.add("742e4659c79d7cad89ea86aab70aea490f23bbfc7e72abd5f0a5d3fb4c84d212");
        demoCertHashes.add("db1264612891406639ecd25c894f256b7c5a6b7e1d9054cbe37b77acd2ddd913");
        demoCertHashes.add("2a5398e20fcb851ec30aa141f37233ee91a802683415be2945c3c312c65c97cf");
        demoCertHashes.add("33129547ce617f784c04e965104b2c671cce9e794d1c64c7efe58c77026246ae");
        demoCertHashes.add("c4af0297cc75546e1905bdfe3934a950161eee11173d979ce929f086fdf9794d");
        demoCertHashes.add("7a355f42c90e7543a267fbe3976c02f619036f5a34ce712995a22b342d83c3ce");
        demoCertHashes.add("a9b5eca1399ec8518081c0d4a21a34eec4589087ce64c04fb01a488f9ad8edc9");

        //new certs 04/2018
        demoCertHashes.add("d14aefe70a592d7a29e14f3ff89c3d0070c99e87d21776aa07d333ee877e758f");
        demoCertHashes.add("54a70016e0837a2b0c5658d1032d7ca32e432c62c55f01a2bf5adcb69a0a7ba9");
        demoCertHashes.add("bdc141ab2272c779d0f242b79063152c49e1b06a2af05e0fd90d505f2b44d5f5");
        demoCertHashes.add("3e839e2b059036a99ee4f742814995f2fb0ced7e9d68a47851f43a3c630b5324");
        demoCertHashes.add("9b13661c073d864c28ad7b13eda67dcb6cbc2f04d116adc7c817c20b4c7ed361");

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                if(Security.getProvider("BC") == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
                return null;
            }
        });

        advancedModulesEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_ADVANCED_MODULES_ENABLED, true);

        ReflectionHelper.init(advancedModulesEnabled);

        ReflectionHelper.registerMngtRestApiHandler(settings);

        log.info("Clustername: {}", settings.get("cluster.name","elasticsearch"));

        if(!transportSSLEnabled) {
            throw new IllegalStateException(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED+" must be set to 'true'");
        }

        if(log.isDebugEnabled() && this.settings.getByPrefix("tribe").size() > 0) {
            log.debug("Tribe configuration detected: {}", this.settings);
        }

        boolean tribeNode = this.settings.get("tribe.name", null) == null && this.settings.getByPrefix("tribe").size() > 0;
        tribeNodeClient = this.settings.get("tribe.name", null) != null;

        log.debug("This node [{}] is a transportClient: {}/tribeNode: {}/tribeNodeClient: {}", settings.get("node.name"), client, tribeNode, tribeNodeClient);

        if(!client) {

//            avoiding document level security and field level security
            dlsFlsAvailable = false;
            dlsFlsConstructor = null;

        } else {
            dlsFlsAvailable = false;
            dlsFlsConstructor = null;
        }

        if(!client && !tribeNodeClient) {
            final List<Path> filesWithWrongPermissions = AccessController.doPrivileged(new PrivilegedAction<List<Path>>() {
                @Override
                public List<Path> run() {

//                    changed as of working of Environment in ES6
                    final Path confPath;
                    if (configPath != null) {
                        confPath = configPath.normalize().toAbsolutePath();
                    } else {
                        confPath = new Environment(settings).configFile().toAbsolutePath();
                    }

                    if(Files.isDirectory(confPath, LinkOption.NOFOLLOW_LINKS)) {
                        try (Stream<Path> s = Files.walk(confPath)) {
                            return s.distinct().filter(p -> checkFilePermissions(p)).collect(Collectors.toList());
                        } catch (Exception e) {
                            log.error(e);
                            return null;
                        }
                    }

                    return Collections.emptyList();
                }
            });

            if(filesWithWrongPermissions != null && filesWithWrongPermissions.size() > 0) {
                for(final Path p: filesWithWrongPermissions) {
                    if(Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
                        log.warn("Directory "+p+" has insecure file permissions (should be 0700)");
                    } else {
                        log.warn("File "+p+" has insecure file permissions (should be 0600)");
                    }
                }
            }
        }

        if(!client && !tribeNodeClient && !settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, false)) {
            //check for demo certificates
            final List<String> files = AccessController.doPrivileged(new PrivilegedAction<List<String>>() {
                @Override
                public List<String> run() {

//                    changed as of working of Environment in ES5
                    final Path confPath;
                    if (configPath != null) {
                        confPath = configPath.normalize().toAbsolutePath();
                    } else {
                        confPath = new Environment(settings).configFile().toAbsolutePath();
                    }

                    if(Files.isDirectory(confPath, LinkOption.NOFOLLOW_LINKS)) {
                        try (Stream<Path> s = Files.walk(confPath)) {
                            return s.distinct().map(p -> sha256(p)).collect(Collectors.toList());
                        } catch (Exception e) {
                            log.error(e);
                            return null;
                        }
                    }

                    return Collections.emptyList();
                }
            });

            if(files != null) {
                demoCertHashes.retainAll(files);
                if(!demoCertHashes.isEmpty()) {
                    log.error("Demo certificates found but "+ConfigConstants.OPENDISTRO_SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES+" is set to false.");
                    throw new RuntimeException("Demo certificates found "+demoCertHashes);
                }
            } else {
                throw new RuntimeException("Unable to look for demo certificates");
            }

        }
    }

    private String sha256(Path p) {

        if(!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            return "";
        }

        if(!Files.isReadable(p)) {
            log.debug("Unreadable file "+p+" found");
            return "";
        }

        try {
            MessageDigest digester = MessageDigest.getInstance("SHA256");
            final String hash =new String(org.bouncycastle.util.encoders.Hex.encode(digester.digest(Files.readAllBytes(p))));
            log.debug(hash +" :: "+p);
            return hash;
        } catch (Exception e) {
            throw new ElasticsearchSecurityException("Unable to digest file "+p, e);
        }
    }

    private boolean checkFilePermissions(final Path p) {

        if (p == null) {
            return false;
        }


        Set<PosixFilePermission> perms;

        try {
            perms = Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS);
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Cannot determine posix file permissions for {} due to {}", p, e);
            }
            //ignore, can happen on windows
            return false;
        }

        if(Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
            if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                // no x for others must be set
                return true;
            }
        } else {
            if (perms.contains(PosixFilePermission.OWNER_EXECUTE) || perms.contains(PosixFilePermission.GROUP_EXECUTE)
                    || perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                // no x must be set
                return true;
            }
        }


        if (perms.contains(PosixFilePermission.OTHERS_READ) || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
            // no permissions for "others" allowed
            return true;
        }

        //if (perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.GROUP_WRITE)) {
        //    // no permissions for "group" allowed
        //    return true;
        //}

        return false;
    }


    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver, Supplier<DiscoveryNodes> nodesInCluster) {

        final List<RestHandler> handlers = new ArrayList<RestHandler>(1);

        if (!client && !tribeNodeClient && !disabled) {

            handlers.addAll(super.getRestHandlers(settings, restController, clusterSettings, indexScopedSettings, settingsFilter, indexNameExpressionResolver, nodesInCluster));

            if(!sslOnly) {

                if (sslCertReloadEnabled) {
                }
//                As if the advanced module is disabled then ReflectionHelper.instantiateMngtRestApiHandler returns the empty list

//                Collection<RestHandler> apiHandler = ReflectionHelper
//                        .instantiateMngtRestApiHandler(settings, configPath, restController, localClient, adminDns, cr, cs, Objects.requireNonNull(principalExtractor),  evaluator, threadPool, Objects.requireNonNull(auditLog));
//                handlers.addAll(apiHandler);
//                log.debug("Added {} management rest handler(s)", apiHandler.size());
            }
        }

        return handlers;
    }

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(final ThreadContext threadContext) {

        if(client || disabled || sslOnly) {
            return (rh) -> rh;
        }

        return (rh) -> securityRestHandler.wrap(rh);
    }






    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays, CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {
        Map<String, Supplier<Transport>> transports = new HashMap<String, Supplier<Transport>>();

        if (transportSSLEnabled) {
            transports.put("com.amazon.opendistroforelasticsearch.security.ssl.http.netty.OpenDistroSecuritySSLNettyTransport",
                    () -> new OpenDistroSecuritySSLNettyTransport(settings, Version.CURRENT, threadPool, networkService, namedWriteableRegistry,
                            circuitBreakerService, odsks, evaluateSslExceptionHandler()));
        }
        return transports;
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays, CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NamedXContentRegistry xContentRegistry, NetworkService networkService, HttpServerTransport.Dispatcher dispatcher) {
        return super.getHttpTransports(settings, threadPool, bigArrays, circuitBreakerService, namedWriteableRegistry, xContentRegistry, networkService, dispatcher);
    }




    @Override
    public Collection<Object> createComponents(Client localClient, ClusterService clusterService, ThreadPool threadPool, ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry) {
        if(sslOnly) {
            return super.createComponents(localClient, clusterService, threadPool, resourceWatcherService, scriptService, xContentRegistry);
        }
        this.threadPool = threadPool;
        this.cs = clusterService;
        this.localClient = localClient;

        final List<Object> components = new ArrayList<Object>();

        if (client || tribeNodeClient || disabled) {
            return components;
        }
        final ClusterInfoHolder cih = new ClusterInfoHolder();
        this.cs.addListener(cih);


        final IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(settings);
        irr = new IndexResolverReplacer(resolver, clusterService, cih);

        sslExceptionHandler = new AuditLogSslExceptionHandler(auditLog);




        adminDns = new AdminDNs(settings);
        //final PrincipalExtractor pe = new DefaultPrincipalExtractor();

        cr = (IndexBaseConfigurationRepository) IndexBaseConfigurationRepository.create(settings, this.configPath, threadPool, localClient, clusterService, auditLog, null);

        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, irr);
        final InternalAuthenticationBackend iab = new InternalAuthenticationBackend(cr);
        final XFFResolver xffResolver = new XFFResolver(threadPool);
        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, xffResolver);
        backendRegistry = new BackendRegistry(settings, configPath, adminDns, xffResolver, iab, auditLog, threadPool);
        cr.subscribeOnChange(ConfigConstants.CONFIGNAME_CONFIG, backendRegistry);

        components.add(adminDns);

//        Adding auditLog to the components causing the guice creation errors during booting process in injest of elasticsearch
//        components.add(auditLog);
        components.add(cr);
        components.add(iab);
        components.add(xffResolver);
        components.add(backendRegistry);

        securityRestHandler = new OpenDistroSecurityRestFilter(backendRegistry, auditLog, threadPool, null, settings, configPath, null);

        return components;

    }

    @Override
    public Settings additionalSettings() {

        if(disabled) {
            return Settings.EMPTY;
        }

        final Settings.Builder builder = Settings.builder();

        builder.put(super.additionalSettings());

        if(!sslOnly){

        }
        return builder.build();
    }
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.addAll(super.getSettings());

        settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, false, Property.NodeScope, Property.Filtered));

        // Protected index settings
        settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered, Property.Final));
        settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_DEFAULT, Function.identity(), Property.NodeScope, Property.Filtered, Property.Final));
        settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_DEFAULT, Function.identity(), Property.NodeScope, Property.Filtered, Property.Final));

        if(!sslOnly) {
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here

            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, Property.NodeScope, Property.Filtered));
            settings.add(Setting.groupSetting(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_IMPERSONATION_DN+".", Property.NodeScope)); //not filtered here

            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_CERT_OID, Property.NodeScope, Property.Filtered));

            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here

            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                    Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                    Property.NodeScope, Property.Filtered));

            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_DISABLED, false, Property.NodeScope, Property.Filtered));

            settings.add(Setting.intSetting(ConfigConstants.OPENDISTRO_SECURITY_CACHE_TTL_MINUTES, 60, 0, Property.NodeScope, Property.Filtered));

            //Security
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_ADVANCED_MODULES_ENABLED, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true, Property.NodeScope, Property.Filtered));


            settings.add(Setting.groupSetting(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".", Property.NodeScope)); //not filtered here

            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_DISABLE_ENVVAR_REPLACEMENT, false, Property.NodeScope, Property.Filtered));

            //settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_DISABLE_TYPE_SECURITY, false, Property.NodeScope, Property.Filtered));

            //TODO remove opendistro_security.tribe.clustername?
            //settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_TRIBE_CLUSTERNAME, Property.NodeScope, Property.Filtered));

            // Security - Audit
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.groupSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ROUTES + ".", Property.NodeScope));
            settings.add(Setting.groupSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS + ".",  Property.NodeScope));
            settings.add(Setting.intSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, 10, Property.NodeScope, Property.Filtered));
            settings.add(Setting.intSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, 100*1000, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true, Property.NodeScope, Property.Filtered));
            final List<String> disabledCategories = new ArrayList<String>(2);
            disabledCategories.add("AUTHENTICATED");
            disabledCategories.add("GRANTED_PRIVILEGES");
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, disabledCategories, Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, disabledCategories, Function.identity(), Property.NodeScope)); //not filtered here
            final List<String> ignoredUsers = new ArrayList<String>(2);
            ignoredUsers.add("kibanaserver");
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, ignoredUsers, Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true, Property.NodeScope, Property.Filtered));


            // Security - Audit - Sink
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_TYPE, Property.NodeScope, Property.Filtered));

            // External ES
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_HTTP_ENDPOINTS, Lists.newArrayList("localhost:9200"), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_USERNAME, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PASSWORD, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_VERIFY_HOSTNAMES, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL_CLIENT_AUTH, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_CONTENT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_CONTENT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_PASSWORD, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_CONTENT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_JKS_CERT_ALIAS, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLED_SSL_CIPHERS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLED_SSL_PROTOCOLS, Collections.emptyList(), Function.identity(), Property.NodeScope));//not filtered here

            // Webhooks
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_URL, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_FORMAT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, true, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, Property.NodeScope, Property.Filtered));

            // Log4j
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG4J_LOGGER_NAME, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG4J_LEVEL, Property.NodeScope, Property.Filtered));


            // Kerberos
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_KERBEROS_KRB5_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL, Property.NodeScope, Property.Filtered));


            // Open Distro Security - REST API
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ROLES_ENABLED, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.groupSetting(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".", Property.NodeScope));

            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, Property.NodeScope, Property.Filtered));
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, Property.NodeScope, Property.Filtered));


            // Compliance
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.listSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList(), Function.identity(), Property.NodeScope)); //not filtered here
            settings.add(Setting.simpleString(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false, Property.NodeScope, Property.Filtered));

            //compat
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, false, Property.NodeScope, Property.Filtered));

            // system integration
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, false, Property.NodeScope, Property.Filtered));

            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false, Property.NodeScope, Property.Filtered));
            settings.add(Setting.boolSetting(ConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD_ENABLED, false, Property.NodeScope, Property.Filtered));
        }

        return settings;
    }

    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();

        if(disabled) {
            return settingsFilter;
        }

        settingsFilter.add("opendistro_security.*");
        return settingsFilter;
    }

//    only logging is done here , it is not present in ES5 hence commenting out
//    @Override
//    public void onNodeStarted() {
//        final Set<ModuleInfo> securityModules = ReflectionHelper.getModulesLoaded();
//        log.info("{} Open Distro Security modules loaded so far: {}", securityModules.size(), securityModules);
//        if(complianceConfig != null && complianceConfig.isEnabled() && complianceConfig.isLogExternalConfig() && !complianceConfig.isExternalConfigLogged()) {
//        	log.info("logging external config");
//        	auditLog.logExternalConfig(complianceConfig.getSettings(), complianceConfig.getEnvironment());
//            complianceConfig.setExternalConfigLogged(true);
//        }
//    }

    //below is a hack because it seems not possible to access RepositoriesService from a non guice class
    //the way of how deguice is organized is really a mess - hope this can be fixed in later versions
    //TODO check if this could be removed

    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {

        if (client || tribeNodeClient || disabled || sslOnly) {
            return Collections.emptyList();
        }

        final List<Class<? extends LifecycleComponent>> services = new ArrayList<>(1);
        services.add(GuiceHolder.class);
        return services;
    }

//    not present in ES5.4 MapperPlugin


    private static String handleKeyword(final String field) {
        if(field != null && field.endsWith(KEYWORD)) {
            return field.substring(0, field.length()-KEYWORD.length());
        }
        return field;
    }

    public static class GuiceHolder implements LifecycleComponent {

        private static RepositoriesService repositoriesService;
        private static RemoteClusterService remoteClusterService;

        @Inject
        public GuiceHolder(final RepositoriesService repositoriesService,
                final TransportService remoteClusterService) {
            GuiceHolder.repositoriesService = repositoriesService;
//            GuiceHolder.remoteClusterService = remoteClusterService.getRemoteClusterService();

            GuiceHolder.remoteClusterService = getRemoteClusterService();
        }

        public static RepositoriesService getRepositoriesService() {
            return repositoriesService;
        }

        public static RemoteClusterService getRemoteClusterService() {
            return remoteClusterService;
        }

        @Override
        public void close() {
        }

        @Override
        public State lifecycleState() {
            return null;
        }

        @Override
        public void addLifecycleListener(LifecycleListener listener) {
        }

        @Override
        public void removeLifecycleListener(LifecycleListener listener) {
        }

        @Override
        public void start() {
        }

        @Override
        public void stop() {
        }

    }
}
