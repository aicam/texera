/*
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

\c texera_db

SET search_path TO texera_db;

BEGIN;

-- shared_output
-- An operator output port published under a name, so other workflows, including other users'
-- pipelines, read it in place. A reader always gets the newest execution of the workflow that has
-- this port's result, and follows it while that execution runs. The port's results are kept when
-- the workflow runs again, until the run after next, so a reader of the previous run is not cut off.
CREATE TABLE IF NOT EXISTS shared_output
(
    soid          SERIAL PRIMARY KEY,
    name          VARCHAR(128) NOT NULL,
    description   TEXT,
    owner_uid     INT NOT NULL,
    wid           INT NOT NULL,
    operator_id   VARCHAR(100) NOT NULL,
    port_id       INT NOT NULL DEFAULT 0,
    creation_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (owner_uid, name),
    UNIQUE (wid, operator_id, port_id),
    FOREIGN KEY (owner_uid) REFERENCES "user"(uid) ON DELETE CASCADE,
    FOREIGN KEY (wid) REFERENCES workflow(wid) ON DELETE CASCADE
);

-- shared_output_user_access
CREATE TABLE IF NOT EXISTS shared_output_user_access
(
    soid      INT NOT NULL,
    uid       INT NOT NULL,
    privilege privilege_enum NOT NULL DEFAULT 'READ',
    PRIMARY KEY (soid, uid),
    FOREIGN KEY (soid) REFERENCES shared_output(soid) ON DELETE CASCADE,
    FOREIGN KEY (uid) REFERENCES "user"(uid) ON DELETE CASCADE
);

COMMIT;
