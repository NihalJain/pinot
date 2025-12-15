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
package org.apache.pinot.core.auth;

import com.google.common.cache.Cache;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.apache.pinot.common.config.provider.AccessControlUserCache;
import org.apache.pinot.common.utils.BcryptUtils;
import org.apache.pinot.spi.config.user.AccessType;
import org.apache.pinot.spi.config.user.ComponentType;
import org.apache.pinot.spi.config.user.RoleType;
import org.apache.pinot.spi.config.user.UserConfig;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


public class BasicAuthUtilsTest {

  private MockedStatic<BcryptUtils> _mockedBcryptUtils;

  @DataProvider(name = "componentTypes")
  public Object[][] componentTypes() {
    return new Object[][]{
        {ComponentType.CONTROLLER}, {ComponentType.BROKER}, {ComponentType.SERVER}
    };
  }

  @BeforeMethod
  public void setUpMocks() {
    _mockedBcryptUtils = Mockito.mockStatic(BcryptUtils.class);
  }

  @AfterMethod
  public void resetMocks() {
    _mockedBcryptUtils.close();
  }

  private AccessControlUserCache mockUserCache(ComponentType componentType, String username, String password) {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    UserConfig userConfig =
        new UserConfig(username, password, componentType.name(), RoleType.ADMIN.name(), null, null, null);

    switch (componentType) {
      case CONTROLLER:
        Mockito.when(userCache.getAllControllerUserConfig()).thenReturn(Collections.singletonList(userConfig));
        break;
      case BROKER:
        Mockito.when(userCache.getAllBrokerUserConfig()).thenReturn(Collections.singletonList(userConfig));
        break;
      case SERVER:
        Mockito.when(userCache.getAllServerUserConfig()).thenReturn(Collections.singletonList(userConfig));
        break;
      default:
        throw new IllegalArgumentException("Unsupported component type: " + componentType);
    }

    Mockito.when(userCache.getUserPasswordAuthCache()).thenReturn(Mockito.mock(Cache.class));
    return userCache;
  }

  private List<String> generateAuthHeaders(String username, String password) {
    String encodedCredentials =
        "Basic " + java.util.Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
    return Collections.singletonList(encodedCredentials);
  }

  @Test(dataProvider = "componentTypes")
  public void testGetPrincipalWithEmptyAuthHeaders(ComponentType componentType) {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    List<String> authHeaders = Collections.emptyList();

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, componentType);
    assertFalse(result.isPresent());

    // Verify that no interactions with userCache, BcryptUtils, or user configurations occur
    Mockito.verify(userCache, Mockito.never()).getUserPasswordAuthCache();
    Mockito.verifyNoInteractions(BcryptUtils.class);
    switch (componentType) {
      case CONTROLLER:
        Mockito.verify(userCache, Mockito.never()).getAllControllerUserConfig();
        break;
      case BROKER:
        Mockito.verify(userCache, Mockito.never()).getAllBrokerUserConfig();
        break;
      case SERVER:
        Mockito.verify(userCache, Mockito.never()).getAllServerUserConfig();
        break;
      default:
        throw new IllegalArgumentException("Unsupported component type: " + componentType);
    }
  }

  @Test(dataProvider = "componentTypes")
  public void testGetPrincipalWithValidAuthHeaders(ComponentType componentType) {
    AccessControlUserCache userCache = mockUserCache(componentType, "admin", "admin");
    _mockedBcryptUtils.when(
            () -> BcryptUtils.checkpwWithCache(Mockito.anyString(), Mockito.anyString(), Mockito.any(Cache.class)))
        .thenReturn(true);

    List<String> authHeaders = generateAuthHeaders("admin", "admin");

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, componentType);
    assertTrue(result.isPresent());
    assertEquals(result.get().getName(), "admin");

    // Verify that the user cache, BcryptUtils, and user configurations are accessed correctly
    Mockito.verify(userCache).getUserPasswordAuthCache();
    _mockedBcryptUtils.verify(
        () -> BcryptUtils.checkpwWithCache("admin", "admin", userCache.getUserPasswordAuthCache()));
    switch (componentType) {
      case CONTROLLER:
        Mockito.verify(userCache).getAllControllerUserConfig();
        break;
      case BROKER:
        Mockito.verify(userCache).getAllBrokerUserConfig();
        break;
      case SERVER:
        Mockito.verify(userCache).getAllServerUserConfig();
        break;
      default:
        throw new IllegalArgumentException("Unsupported component type: " + componentType);
    }
  }

  @Test
  public void testGetPrincipalWithInvalidAuthHeaders() {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    UserConfig userConfig =
        new UserConfig("admin", "admin", ComponentType.CONTROLLER.name(), RoleType.ADMIN.name(), null, null, null);
    Mockito.when(userCache.getAllControllerUserConfig()).thenReturn(Collections.singletonList(userConfig));

    List<String> authHeaders = Collections.singletonList("Basic dummy");

    try {
      BasicAuthUtils.getPrincipal(authHeaders, userCache, ComponentType.CONTROLLER);
      // TODO Fix below
      Assert.fail("Did not expect to reach here");
    } catch (IllegalArgumentException ex) {
      // failed as expected
    }
    Mockito.verifyNoInteractions(BcryptUtils.class);
  }

  @Test(dataProvider = "componentTypes")
  public void testGetPrincipalWithIncorrectPassword(ComponentType componentType) {
    AccessControlUserCache userCache = mockUserCache(componentType, "admin", "admin");
    _mockedBcryptUtils.when(
            () -> BcryptUtils.checkpwWithCache(Mockito.anyString(), Mockito.anyString(), Mockito.any(Cache.class)))
        .thenReturn(false);

    List<String> authHeaders = generateAuthHeaders("admin", "wrongPassword");

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, componentType);
    assertFalse(result.isPresent());

    // Verify that the user cache, BcryptUtils, and user configurations are accessed correctly
    Mockito.verify(userCache).getUserPasswordAuthCache();
    _mockedBcryptUtils.verify(
        () -> BcryptUtils.checkpwWithCache("wrongPassword", "admin", userCache.getUserPasswordAuthCache()));
    switch (componentType) {
      case CONTROLLER:
        Mockito.verify(userCache).getAllControllerUserConfig();
        break;
      case BROKER:
        Mockito.verify(userCache).getAllBrokerUserConfig();
        break;
      case SERVER:
        Mockito.verify(userCache).getAllServerUserConfig();
        break;
      default:
        throw new IllegalArgumentException("Unsupported component type: " + componentType);
    }
  }

  @Test(dataProvider = "componentTypes")
  public void testGetPrincipalWithEmptyUserCache(ComponentType componentType) {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    // Mock the user cache to return null for user configurations
    switch (componentType) {
      case CONTROLLER:
        Mockito.when(userCache.getAllControllerUserConfig()).thenReturn(new ArrayList<>());
        break;
      case BROKER:
        Mockito.when(userCache.getAllBrokerUserConfig()).thenReturn(new ArrayList<>());
        break;
      case SERVER:
        Mockito.when(userCache.getAllServerUserConfig()).thenReturn(new ArrayList<>());
        break;
      default:
        throw new IllegalArgumentException("Unsupported component type: " + componentType);
    }
    Mockito.when(userCache.getUserPasswordAuthCache()).thenReturn(Mockito.mock(Cache.class));

    List<String> authHeaders = generateAuthHeaders("admin", "admin");

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, componentType);
    assertFalse(result.isPresent());

    // Verify that no interactions with userCache, BcryptUtils, or user configurations occur
    Mockito.verify(userCache, Mockito.never()).getUserPasswordAuthCache();
    _mockedBcryptUtils.verifyNoInteractions();
    switch (componentType) {
      case CONTROLLER:
        Mockito.verify(userCache, Mockito.times(1)).getAllControllerUserConfig();
        break;
      case BROKER:
        Mockito.verify(userCache, Mockito.times(1)).getAllBrokerUserConfig();
        break;
      case SERVER:
        Mockito.verify(userCache, Mockito.times(1)).getAllServerUserConfig();
        break;
      default:
        throw new IllegalArgumentException("Unsupported component type: " + componentType);
    }
  }

  @Test(dataProvider = "componentTypes")
  public void testExtractBasicAuthPrincipals(ComponentType componentType) {
    UserConfig userConfig = new UserConfig("admin", "password", componentType.name(), RoleType.ADMIN.name(),
        Arrays.asList("table1", "table2"), Arrays.asList("excludeTable1"),
        Arrays.asList(AccessType.READ, AccessType.DELETE));

    List<ZkBasicAuthPrincipal> principals =
        BasicAuthUtils.extractBasicAuthPrincipals(Collections.singletonList(userConfig));

    assertEquals(principals.size(), 1);
    ZkBasicAuthPrincipal principal = principals.get(0);
    assertEquals(principal.getName(), "admin");
    assertEquals(principal.getPassword(), "password");
    assertEquals(principal.getToken(), "Basic YWRtaW46cGFzc3dvcmQ");
    assertEquals(principal.getComponent(), componentType.name());
    assertEquals(principal.getRole(), RoleType.ADMIN.name());
    assertTrue(principal.hasTable("table1"));
    assertFalse(principal.hasTable("excludeTable1"));
    assertTrue(principal.hasPermission(AccessType.READ.name()));
    assertTrue(principal.hasPermission(AccessType.DELETE.name()));
    assertFalse(principal.hasPermission(AccessType.CREATE.name()));
    assertFalse(principal.hasPermission(AccessType.UPDATE.name()));
  }

  @Test(dataProvider = "componentTypes")
  public void testExtractBasicAuthPrincipalsWithEmptyTables(ComponentType componentType) {
    UserConfig userConfig = new UserConfig("admin", "password", componentType.name(), RoleType.ADMIN.name(),
        Collections.emptyList(), Arrays.asList("excludeTable1"),
        Arrays.asList(AccessType.READ, AccessType.DELETE));

    List<ZkBasicAuthPrincipal> principals =
        BasicAuthUtils.extractBasicAuthPrincipals(Collections.singletonList(userConfig));

    assertEquals(principals.size(), 1);
    ZkBasicAuthPrincipal principal = principals.get(0);
    assertEquals(principal.getName(), "admin");
    assertEquals(principal.getPassword(), "password");
    assertEquals(principal.getToken(), "Basic YWRtaW46cGFzc3dvcmQ");
    assertEquals(principal.getComponent(), componentType.name());
    assertEquals(principal.getRole(), RoleType.ADMIN.name());
    // If no tables are specified, the principal should have access to all tables, except the excluded ones
    assertTrue(principal.hasTable("table1"));
    assertTrue(principal.hasTable("table2"));
    assertFalse(principal.hasTable("excludeTable1"));
    assertTrue(principal.hasPermission(AccessType.READ.name()));
    assertTrue(principal.hasPermission(AccessType.DELETE.name()));
    assertFalse(principal.hasPermission(AccessType.CREATE.name()));
    assertFalse(principal.hasPermission(AccessType.UPDATE.name()));
  }

  @Test(dataProvider = "componentTypes")
  public void testExtractBasicAuthPrincipalsWithEmptyPermissions(ComponentType componentType) {
    UserConfig userConfig = new UserConfig("admin", "password", componentType.name(), RoleType.ADMIN.name(),
        Arrays.asList("table1", "table2"), Arrays.asList("excludeTable1"), Arrays.asList());

    List<ZkBasicAuthPrincipal> principals =
        BasicAuthUtils.extractBasicAuthPrincipals(Collections.singletonList(userConfig));

    assertEquals(principals.size(), 1);
    ZkBasicAuthPrincipal principal = principals.get(0);
    assertEquals(principal.getName(), "admin");
    assertEquals(principal.getPassword(), "password");
    assertEquals(principal.getToken(), "Basic YWRtaW46cGFzc3dvcmQ");
    assertEquals(principal.getComponent(), componentType.name());
    assertEquals(principal.getRole(), RoleType.ADMIN.name());
    assertTrue(principal.hasTable("table1"));
    assertFalse(principal.hasTable("excludeTable1"));
    // If no permissions are specified, the principal should have access to all permissions
    assertTrue(principal.hasPermission(AccessType.READ.name()));
    assertTrue(principal.hasPermission(AccessType.DELETE.name()));
    assertTrue(principal.hasPermission(AccessType.CREATE.name()));
    assertTrue(principal.hasPermission(AccessType.UPDATE.name()));
  }
}
