/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pinot.integration.tests.access;

import java.util.Map;
import org.apache.pinot.integration.tests.ZKAuthTestUtils;
import org.apache.pinot.spi.env.PinotConfiguration;


public class ZKAuthBatchIntegrationTest extends AbstractAuthBatchIntegrationTest {

  @Override
  protected void overrideControllerConf(Map<String, Object> properties) {
    ZKAuthTestUtils.addControllerConfiguration(properties);
  }

  @Override
  protected void overrideBrokerConf(PinotConfiguration brokerConf) {
    ZKAuthTestUtils.addBrokerConfiguration(brokerConf);
  }

  @Override
  protected void overrideServerConf(PinotConfiguration serverConf) {
    ZKAuthTestUtils.addServerConfiguration(serverConf);
  }

  @Override
  protected void overrideMinionConf(PinotConfiguration minionConf) {
    ZKAuthTestUtils.addMinionConfiguration(minionConf);
  }

  @Override
  protected String getAuthToken() {
    return ZKAuthTestUtils.AUTH_TOKEN;
  }

  @Override
  protected Map<String, String> getAuthHeader() {
    return ZKAuthTestUtils.AUTH_HEADER;
  }

  @Override
  protected Map<String, String> getUserAuthHeader() {
    return ZKAuthTestUtils.AUTH_HEADER_USER;
  }
}
