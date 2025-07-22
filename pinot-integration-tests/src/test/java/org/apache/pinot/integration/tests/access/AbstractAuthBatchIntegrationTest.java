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

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Preconditions;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.pinot.common.auth.AuthProviderUtils;
import org.apache.pinot.common.exception.HttpErrorStatusException;
import org.apache.pinot.integration.tests.ClusterTest;
import org.apache.pinot.spi.utils.JsonUtils;
import org.apache.pinot.tools.BootstrapTableTool;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;


public abstract class AbstractAuthBatchIntegrationTest extends ClusterTest {
  private static final String BOOTSTRAP_DATA_DIR = "/examples/batch/baseballStats";
  private static final String SCHEMA_FILE = "baseballStats_schema.json";
  private static final String CONFIG_FILE = "baseballStats_offline_table_config.json";
  private static final String DATA_FILE = "baseballStats_data.csv";
  private static final String JOB_FILE = "ingestionJobSpec.yaml";

  @BeforeClass
  public void setUp()
      throws Exception {
    // Start Zookeeper
    startZk();
    // Start the Pinot cluster
    startController();
    startBroker();
    startServer();
    startMinion();
  }

  @AfterClass(alwaysRun = true)
  public void tearDown()
      throws Exception {
    stopMinion();
    stopServer();
    stopBroker();
    stopController();
    stopZk();
  }

  @Test
  public void testBrokerNoAuth() {
    try {
      sendPostRequest("http://localhost:" + getRandomBrokerPort() + "/query/sql", "{\"sql\":\"SELECT now()\"}");
    } catch (IOException e) {
      HttpErrorStatusException httpErrorStatusException = (HttpErrorStatusException) e.getCause();
      Assert.assertEquals(httpErrorStatusException.getStatusCode(), 401, "must return 401");
    }
  }

  @Test
  public void testBroker()
      throws Exception {
    JsonNode response = JsonUtils.stringToJsonNode(
        sendPostRequest("http://localhost:" + getRandomBrokerPort() + "/query/sql", "{\"sql\":\"SELECT now()\"}",
            getAuthHeader()));
    Assert.assertEquals(response.get("resultTable").get("dataSchema").get("columnDataTypes").get(0).asText(), "LONG",
        "must return result with LONG value");
    Assert.assertTrue(response.get("exceptions").isEmpty(), "must not return exception");
  }

  @Test
  public void testControllerGetTables()
      throws Exception {
    JsonNode response = JsonUtils.stringToJsonNode(
        sendGetRequest("http://localhost:" + getControllerPort() + "/tables", getAuthHeader()));
    Assert.assertTrue(response.get("tables").isArray(), "must return table array");
  }

  @Test
  public void testControllerGetTablesNoAuth() {
    try {
      sendGetRequest("http://localhost:" + getControllerPort() + "/tables");
    } catch (IOException e) {
      Assert.assertTrue(e.getMessage().contains("401"));
    }
  }

  @Test
  public void testIngestionBatch()
      throws Exception {
    File quickstartTmpDir = new File(FileUtils.getTempDirectory(), String.valueOf(System.currentTimeMillis()));
    FileUtils.forceDeleteOnExit(quickstartTmpDir);

    File baseDir = new File(quickstartTmpDir, "baseballStats");
    File dataDir = new File(baseDir, "rawdata");
    File schemaFile = new File(baseDir, SCHEMA_FILE);
    File configFile = new File(baseDir, CONFIG_FILE);
    File dataFile = new File(dataDir, DATA_FILE);
    File jobFile = new File(baseDir, JOB_FILE);
    Preconditions.checkState(dataDir.mkdirs());

    copyResourcesToFiles(baseDir, schemaFile, configFile, dataFile, jobFile);

    String jobFileContents = IOUtils.toString(new FileInputStream(jobFile));
    IOUtils.write(jobFileContents.replaceAll("9000", String.valueOf(getControllerPort())),
        new FileOutputStream(jobFile));

    new BootstrapTableTool("http", "localhost", getControllerPort(), baseDir.getAbsolutePath(),
        AuthProviderUtils.makeAuthProvider(getAuthToken())).execute();

    Thread.sleep(5000);

    // admin with full access
    testBrokerQueryWithAuth();

    // user with valid auth but no table access - must return 403
    testBrokerQueryWithoutAccess();
  }

  protected abstract String getAuthToken();

  protected abstract Map<String, String> getAuthHeader();

  private void testBrokerQueryWithAuth()
      throws Exception {
    JsonNode response = JsonUtils.stringToJsonNode(
        sendPostRequest("http://localhost:" + getRandomBrokerPort() + "/query/sql",
            "{\"sql\":\"SELECT count(*) FROM baseballStats\"}", getAuthHeader()));
    Assert.assertEquals(response.get("resultTable").get("dataSchema").get("columnDataTypes").get(0).asText(), "LONG",
        "must return result with LONG value");
    Assert.assertEquals(response.get("resultTable").get("dataSchema").get("columnNames").get(0).asText(), "count(*)",
        "must return column name 'count(*)");
    Assert.assertEquals(response.get("resultTable").get("rows").get(0).get(0).asInt(), 97889,
        "must return row count 97889");
    Assert.assertTrue(response.get("exceptions").isEmpty(), "must not return exception");
  }

  private void testBrokerQueryWithoutAccess() {
    try {
      sendPostRequest("http://localhost:" + getRandomBrokerPort() + "/query/sql",
          "{\"sql\":\"SELECT count(*) FROM baseballStats\"}", getUserAuthHeader());
    } catch (IOException e) {
      HttpErrorStatusException httpErrorStatusException = (HttpErrorStatusException) e.getCause();
      Assert.assertEquals(httpErrorStatusException.getStatusCode(), 403, "must return 403");
    }
  }

  protected abstract Map<String, String> getUserAuthHeader();

  private void copyResourcesToFiles(File baseDir, File schemaFile, File configFile, File dataFile, File jobFile)
      throws IOException {
    FileUtils.copyURLToFile(getClass().getResource(BOOTSTRAP_DATA_DIR + "/" + SCHEMA_FILE), schemaFile);
    FileUtils.copyURLToFile(getClass().getResource(BOOTSTRAP_DATA_DIR + "/" + CONFIG_FILE), configFile);
    FileUtils.copyURLToFile(getClass().getResource(BOOTSTRAP_DATA_DIR + "/rawdata/" + DATA_FILE), dataFile);
    FileUtils.copyURLToFile(getClass().getResource(BOOTSTRAP_DATA_DIR + "/" + JOB_FILE), jobFile);
  }
}
