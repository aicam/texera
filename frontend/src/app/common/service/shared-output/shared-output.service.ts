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

import { HttpClient } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { Observable } from "rxjs";
import { AppSettings } from "../../app-setting";

export const SHARED_OUTPUT_BASE_URL = `${AppSettings.getApiEndpoint()}/shared-output`;

/** An operator output published under a name; `reference` is what a Shared Output source names. */
export interface SharedOutputEntry {
  soid: number;
  reference: string;
  name: string;
  description: string;
  ownerEmail: string;
  wid: number;
  workflowName: string;
  operatorId: string;
  portId: number;
  isOwner: boolean;
}

export interface SharedOutputAccess {
  email: string;
  privilege: string;
}

@Injectable({ providedIn: "root" })
export class SharedOutputService {
  constructor(private http: HttpClient) {}

  /** The outputs the user published or was given access to. */
  public list(): Observable<SharedOutputEntry[]> {
    return this.http.get<SharedOutputEntry[]>(`${SHARED_OUTPUT_BASE_URL}/list`);
  }

  public ofWorkflow(wid: number): Observable<SharedOutputEntry[]> {
    return this.http.get<SharedOutputEntry[]>(`${SHARED_OUTPUT_BASE_URL}/workflow/${wid}`);
  }

  public publish(wid: number, operatorId: string, name: string, description: string): Observable<SharedOutputEntry> {
    return this.http.post<SharedOutputEntry>(`${SHARED_OUTPUT_BASE_URL}/publish`, {
      wid,
      operatorId,
      name,
      description,
    });
  }

  public unpublish(soid: number): Observable<void> {
    return this.http.delete<void>(`${SHARED_OUTPUT_BASE_URL}/${soid}`);
  }

  public access(soid: number): Observable<SharedOutputAccess[]> {
    return this.http.get<SharedOutputAccess[]>(`${SHARED_OUTPUT_BASE_URL}/${soid}/access`);
  }

  public share(soid: number, email: string): Observable<void> {
    return this.http.post<void>(`${SHARED_OUTPUT_BASE_URL}/${soid}/share`, { email });
  }

  public revoke(soid: number, email: string): Observable<void> {
    return this.http.delete<void>(`${SHARED_OUTPUT_BASE_URL}/${soid}/share/${encodeURIComponent(email)}`);
  }
}
