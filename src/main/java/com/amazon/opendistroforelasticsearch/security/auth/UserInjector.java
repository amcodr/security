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

package com.amazon.opendistroforelasticsearch.security.auth;

import com.amazon.opendistroforelasticsearch.security.http.XFFResolver;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;


public class UserInjector {

    protected final Logger log = LogManager.getLogger(UserInjector.class);

    private final ThreadPool threadPool;
    private final AuditLog auditLog;
    private final XFFResolver xffResolver;
    private final Boolean injectUserEnabled;

    UserInjector(Settings settings, ThreadPool threadPool, AuditLog auditLog, XFFResolver xffResolver) {
        this.threadPool = threadPool;
        this.auditLog = auditLog;
        this.xffResolver = xffResolver;
        this.injectUserEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false);

    }

    boolean injectUser(RestRequest request) {

        if (!injectUserEnabled) {
            return false;
        }

//        returning false as this is for injecting user for transport request
        return false;

    }
}
