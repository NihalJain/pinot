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
package org.apache.pinot.broker.broker;

import com.google.common.base.Preconditions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.ws.rs.NotAuthorizedException;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.broker.api.HttpRequesterIdentity;
import org.apache.pinot.broker.grpc.GrpcRequesterIdentity;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.core.auth.BasicAuthPrincipal;
import org.apache.pinot.spi.auth.AuthorizationResult;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.TableRowColAccessResult;
import org.apache.pinot.spi.auth.TableRowColAccessResultImpl;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.utils.builder.TableNameBuilder;


/**
 * Abstract class for basic authentication access control implementations of the broker.
 */
abstract class AbstractBasicAuthAccessControl implements AccessControl {
  protected static final String HEADER_AUTHORIZATION = "authorization";
  protected static final String BASIC_AUTH = "Basic";

  /**
   * Returns whether the client has permission to access the endpoints which are not table level for the given access
   * type.
   * - If the requester identity is not authorized, throws a NotAuthorizedException.
   * - Else, returns success.
   *
   * @param requesterIdentity requester identity
   */
  @Override
  public AuthorizationResult authorize(RequesterIdentity requesterIdentity) {
    return authorize(requesterIdentity, (BrokerRequest) null);
  }

  /**
   * Authorizes the requester identity to access the given broker request.
   * - If the requester identity is not authorized, throws a NotAuthorizedException.
   * - If the broker request is null or does not have a table name, returns success.
   * - If the principal has access to the table, returns success.
   * - If the principal does not have access to the table, returns failure.
   *
   * @param requesterIdentity Requester identity
   * @param brokerRequest Broker request to authorize
   */
  @Override
  public AuthorizationResult authorize(RequesterIdentity requesterIdentity, BrokerRequest brokerRequest) {
    Optional<? extends BasicAuthPrincipal> principalOpt = getPrincipal(requesterIdentity);
    if (!principalOpt.isPresent()) {
      throw new NotAuthorizedException(BASIC_AUTH);
    }

    // Return success if broker request is null or does not have a table name
    if (brokerRequest == null
        || !brokerRequest.isSetQuerySource()
        || !brokerRequest.getQuerySource().isSetTableName()) {
      // No table restrictions? Accept
      return TableAuthorizationResult.success();
    }

    // If table name is present, check if the principal has access to it
    return authorizeInternal(principalOpt, Collections.singleton(brokerRequest.getQuerySource().getTableName()));
  }

  /**
   * Authorizes the requester identity to access the given tables.
   * - If the requester identity is not authorized, throws a NotAuthorizedException.
   * - If the tables are null or empty, returns success.
   * - If the principal has access to all the tables, returns success.
   * - If the principal does not have access to all the tables, returns failure with the failed tables.
   *
   * @param requesterIdentity Requester identity
   * @param tables Tables to authorize
   */
  @Override
  public TableAuthorizationResult authorize(RequesterIdentity requesterIdentity, Set<String> tables) {
    Optional<? extends BasicAuthPrincipal> principalOpt = getPrincipal(requesterIdentity);
    if (!principalOpt.isPresent()) {
      throw new NotAuthorizedException(BASIC_AUTH);
    }

    return authorizeInternal(principalOpt, tables);
  }

  @Override
  public TableRowColAccessResult getRowColFilters(RequesterIdentity requesterIdentity, String table) {
    Optional<? extends BasicAuthPrincipal> principalOpt = getPrincipal(requesterIdentity);

    Preconditions.checkState(principalOpt.isPresent(), "Principal is not authorized");
    Preconditions.checkState(table != null, "Table cannot be null");

    TableRowColAccessResult tableRowColAccessResult = new TableRowColAccessResultImpl();
    BasicAuthPrincipal principal = principalOpt.get();

    //precondition: The principal should have the table.
    Preconditions.checkArgument(principal.hasTable(table),
        "Principal: " + principal.getName() + " does not have access to table: " + table);

    Optional<List<String>> rlsFiltersMaybe = principal.getRLSFilters(table);
    rlsFiltersMaybe.ifPresent(tableRowColAccessResult::setRLSFilters);

    return tableRowColAccessResult;
  }

  private TableAuthorizationResult authorizeInternal(Optional<? extends BasicAuthPrincipal> principalOpt,
      Set<String> tables) {
    // Return success, if tables is null or empty
    if (CollectionUtils.isEmpty(tables)) {
      return TableAuthorizationResult.success();
    }

    // Check if the principal has access to all the tables
    BasicAuthPrincipal principal = principalOpt.get();
    Set<String> failedTables = new HashSet<>();
    for (String table : tables) {
      if (!principal.hasTable(TableNameBuilder.extractRawTableName(table))) {
        failedTables.add(table);
      }
    }

    // Return success if all tables are accessible
    if (failedTables.isEmpty()) {
      return TableAuthorizationResult.success();
    }

    // Return failed tables
    return new TableAuthorizationResult(failedTables);
  }

  /**
   * * Return the tokens from the given requester identity.
   *
   * @param requesterIdentity identity of the requester
   * @throws UnsupportedOperationException if the requester identity is not an instance of GrpcRequesterIdentity or
   *                                       HttpRequesterIdentity
   */
  protected List<String> getTokens(RequesterIdentity requesterIdentity) {
    Preconditions.checkArgument(requesterIdentity instanceof HttpRequesterIdentity
            || requesterIdentity instanceof GrpcRequesterIdentity,
        "HttpRequesterIdentity or GrpcRequesterIdentity required");

    if (requesterIdentity instanceof HttpRequesterIdentity) {
      HttpRequesterIdentity identity = (HttpRequesterIdentity) requesterIdentity;
      return new ArrayList<>(identity.getHttpHeaders().get(HEADER_AUTHORIZATION));
    }

    if (requesterIdentity instanceof GrpcRequesterIdentity) {
      GrpcRequesterIdentity identity = (GrpcRequesterIdentity) requesterIdentity;
      for (String key : identity.getMetadata().keySet()) {
        if (HEADER_AUTHORIZATION.equalsIgnoreCase(key)) {
          return new ArrayList<>(identity.getMetadata().get(key));
        }
      }
    }

    return Collections.emptyList();
  }

  /**
   * Returns the principal for the given requester identity.
   * @param requesterIdentity Requester identity
   */
  protected abstract Optional<? extends BasicAuthPrincipal> getPrincipal(RequesterIdentity requesterIdentity);
}
