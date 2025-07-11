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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * Container object for basic auth principal
 */
public class BasicAuthPrincipal {
  private final String _name;
  private final String _token;
  private final Set<String> _tables;
  private final Set<String> _excludeTables;
  private final Set<String> _permissions;
  //key: table name, val: list of RLS filters applicable for that table.
  private final Map<String, List<String>> _rlsFilters;

  public BasicAuthPrincipal(String name, String token, Set<String> tables, Set<String> excludeTables,
      Set<String> permissions) {
    this(name, token, tables, excludeTables, permissions, null);
  }

  public BasicAuthPrincipal(String name, String token, Set<String> tables, Set<String> excludeTables,
      Set<String> permissions, Map<String, List<String>> rlsFilters) {
    _name = name;
    _token = token;
    _tables = tables;
    _excludeTables = excludeTables;
    _permissions = permissions.stream().map(s -> s.toLowerCase()).collect(Collectors.toSet());
    _rlsFilters = rlsFilters;
  }

  public String getName() {
    return _name;
  }

  public String getToken() {
    return _token;
  }

  public boolean hasTable(String tableName) {
    return isTableIncluded(tableName) && isTableNotExcluded(tableName);
  }

  private boolean isTableIncluded(String tableName) {
    return _tables.isEmpty() || _tables.contains(tableName);
  }

  private boolean isTableNotExcluded(String tableName) {
    return !_excludeTables.contains(tableName);
  }

  public boolean hasPermission(String permission) {
    return _permissions.isEmpty() || _permissions.contains(permission.toLowerCase());
  }

  /**
   * Gets the Row-Level Security (RLS) filter configured for the given table.
   * The RLS filter is applied only if the user has access to the table
   * (as determined by {@link #hasTable(String)}).
   *
   * @param tableName The name of the table.
   * @return An {@link java.util.Optional} containing the RLS filter string if configured for this principal and table,
   * otherwise {@link java.util.Optional#empty()}.
   */
  public Optional<List<String>> getRLSFilters(String tableName) {
    return Optional.ofNullable(_rlsFilters.get(tableName));
  }

  @Override
  public String toString() {
    return "BasicAuthPrincipal{"
        + "_name='" + _name + '\''
        + ", _token='" + _token + '\''
        + ", _tables=" + _tables + '\''
        + ", _permissions=" + _permissions + '\''
        + ",_rlsFilters=" + _rlsFilters
        + '}';
  }
}
