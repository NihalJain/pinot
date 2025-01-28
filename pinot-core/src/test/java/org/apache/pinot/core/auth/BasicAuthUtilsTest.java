package org.apache.pinot.core.auth;

import com.google.common.cache.Cache;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.apache.pinot.common.config.provider.AccessControlUserCache;
import org.apache.pinot.common.utils.BcryptUtils;
import org.apache.pinot.spi.config.user.ComponentType;
import org.apache.pinot.spi.config.user.RoleType;
import org.apache.pinot.spi.config.user.UserConfig;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;


public class BasicAuthUtilsTest {

  private MockedStatic<BcryptUtils> mockedBcryptUtils;

  @BeforeMethod
  public void setUpMocks() {
    mockedBcryptUtils = Mockito.mockStatic(BcryptUtils.class);
  }

  @AfterMethod
  public void resetMocks() {
    mockedBcryptUtils.close();
  }

  @Test
  public void testGetPrincipalWithEmptyAuthHeaders() {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    List<String> authHeaders = Collections.emptyList();

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, ComponentType.CONTROLLER);
    assertFalse(result.isPresent());
    Mockito.verifyNoInteractions(BcryptUtils.class);
  }

  @Test
  public void testGetPrincipalWithValidAuthHeaders() {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    UserConfig userConfig =
        new UserConfig("admin", "admin", ComponentType.CONTROLLER.name(), RoleType.ADMIN.name(), null, null);
    Mockito.when(userCache.getAllControllerUserConfig()).thenReturn(Collections.singletonList(userConfig));
    Mockito.when(userCache.getUserPasswordAuthCache()).thenReturn(Mockito.mock(Cache.class));
    mockedBcryptUtils.when(
            () -> BcryptUtils.checkpwWithCache(Mockito.anyString(), Mockito.anyString(), Mockito.any(Cache.class)))
        .thenReturn(true);

    List<String> authHeaders = Collections.singletonList("Basic YWRtaW46YWRtaW4=");

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, ComponentType.CONTROLLER);
    assertTrue(result.isPresent());
    assertEquals(result.get().getName(), "admin");
  }

  @Ignore
  public void testGetPrincipalWithInvalidAuthHeaders() {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    UserConfig userConfig =
        new UserConfig("admin", "admin", ComponentType.CONTROLLER.name(), RoleType.ADMIN.name(), null, null);
    Mockito.when(userCache.getAllControllerUserConfig()).thenReturn(Collections.singletonList(userConfig));

    List<String> authHeaders = Collections.singletonList("Basic dummy");

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, ComponentType.CONTROLLER);
    assertFalse(result.isPresent());
    Mockito.verifyNoInteractions(BcryptUtils.class);
  }

  @Test
  public void testGetPrincipalWithIncorrectPassword() {
    AccessControlUserCache userCache = Mockito.mock(AccessControlUserCache.class);
    UserConfig userConfig =
        new UserConfig("admin", "admin", ComponentType.CONTROLLER.name(), RoleType.ADMIN.name(), null, null);
    Mockito.when(userCache.getAllControllerUserConfig()).thenReturn(Collections.singletonList(userConfig));
    mockedBcryptUtils.when(
            () -> BcryptUtils.checkpwWithCache(Mockito.anyString(), Mockito.anyString(), Mockito.any(Cache.class)))
        .thenReturn(false);

    List<String> authHeaders = Collections.singletonList("Basic YWRtaW46YWRtaW4x");

    Optional<ZkBasicAuthPrincipal> result = BasicAuthUtils.getPrincipal(authHeaders, userCache, ComponentType.CONTROLLER);
    assertFalse(result.isPresent());
  }
}