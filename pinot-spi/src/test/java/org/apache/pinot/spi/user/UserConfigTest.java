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
package org.apache.pinot.spi.user;

import java.util.Arrays;
import java.util.Collections;
import org.apache.pinot.spi.config.user.AccessType;
import org.apache.pinot.spi.config.user.ComponentType;
import org.apache.pinot.spi.config.user.RoleType;
import org.apache.pinot.spi.config.user.UserConfig;
import org.testng.annotations.Test;

import static org.testng.Assert.*;


public class UserConfigTest {

  @Test
  void testValidUserConfigCreation() {
    UserConfig userConfig = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", Arrays.asList("table1", "table2"),
        Collections.singletonList("excludeTable"), Collections.singletonList(AccessType.READ));

    assertEquals("testUser", userConfig.getUserName());
    assertEquals("testPass", userConfig.getPassword());
    assertEquals(ComponentType.BROKER, userConfig.getComponentType());
    assertEquals(RoleType.ADMIN, userConfig.getRoleType());
    assertEquals(Arrays.asList("table1", "table2"), userConfig.getTables());
    assertEquals(Collections.singletonList("excludeTable"), userConfig.getExcludeTables());
    assertEquals(Collections.singletonList(AccessType.READ), userConfig.getPermissios());
  }

  @Test
  void testInvalidUserConfigCreation() {
    // Test invalid configurations for username
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig(null, "testPass", "BROKER", "ADMIN", null, null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("", "testPass", "BROKER", "ADMIN", null, null, null));

    // Test invalid configurations for password
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", null, "BROKER", "ADMIN", null, null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "", "BROKER", "ADMIN", null, null, null));

    // Test invalid configurations for component type
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "INVALID_COMPONENT", "ADMIN", null, null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "", "ADMIN", null, null, null));

    // Test invalid configurations for role type
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "INVALID_ROLE", null, null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "", null, null, null));

    // Test invalid configurations for tables
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "ADMIN", Arrays.asList("validTable", null), null, null));
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "ADMIN", Arrays.asList("validTable", ""), null, null));

    // Test invalid configurations for exclude tables
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, Arrays.asList("validExcludeTable", null),
            null));
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, Arrays.asList("validExcludeTable", ""),
            null));

    // Test invalid configurations for permissions
    assertThrows(IllegalArgumentException.class,
        () -> new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null,
            Arrays.asList(AccessType.READ, null)));
  }

  @Test
  void testGetUsernameWithComponent() {
    UserConfig userConfig = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null, null);

    assertEquals("testUser_BROKER", userConfig.getUsernameWithComponent());
  }

  @Test
  void testIsExist() {
    UserConfig userConfig = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null, null);

    assertTrue(userConfig.isExist("testUser", ComponentType.BROKER));
    assertFalse(userConfig.isExist("testUser", ComponentType.CONTROLLER));
    assertFalse(userConfig.isExist("otherUser", ComponentType.BROKER));
  }

  @Test
  void testEqualsAndHashCode() {
    UserConfig userConfig1 = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null, null);

    UserConfig userConfig2 = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null, null);

    UserConfig userConfig3 = new UserConfig("otherUser", "testPass", "BROKER", "ADMIN", null, null, null);

    assertEquals(userConfig1, userConfig2);
    assertNotEquals(userConfig1, userConfig3);
    assertEquals(userConfig1.hashCode(), userConfig2.hashCode());
    assertNotEquals(userConfig1.hashCode(), userConfig3.hashCode());
  }

  @Test
  void testSetRole() {
    UserConfig userConfig = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null, null);

    userConfig.setRole("USER");
    assertEquals(RoleType.USER, userConfig.getRoleType());
  }

  @Test
  void testSetPassword() {
    UserConfig userConfig = new UserConfig("testUser", "testPass", "BROKER", "ADMIN", null, null, null);

    userConfig.setPassword("newPass");
    assertEquals("newPass", userConfig.getPassword());
  }
}
