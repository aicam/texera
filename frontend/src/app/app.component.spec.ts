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

import { CommonModule } from "@angular/common";
import { ComponentFixture, TestBed } from "@angular/core/testing";
import { By } from "@angular/platform-browser";
import { RouterTestingModule } from "@angular/router/testing";

import { AppComponent } from "./app.component";
import { GuiConfigService } from "./common/service/gui-config.service";
import { MockGuiConfigService } from "./common/service/gui-config.service.mock";

describe("AppComponent", () => {
  let fixture: ComponentFixture<AppComponent>;
  let configService: MockGuiConfigService;

  function build(configLoaded: boolean): void {
    TestBed.configureTestingModule({
      imports: [CommonModule, RouterTestingModule],
      declarations: [AppComponent],
      providers: [{ provide: GuiConfigService, useClass: MockGuiConfigService }],
    });

    configService = TestBed.inject(GuiConfigService) as unknown as MockGuiConfigService;
    if (configLoaded) {
      configService.setConfig({ copilotEnabled: true });
    } else {
      // Make `config.env` throw so AppComponent reports the configuration error.
      Object.defineProperty(configService, "env", {
        get() {
          throw new Error("config not loaded");
        },
        configurable: true,
      });
    }
    fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
  }

  it("renders the router outlet when configuration loads", () => {
    build(true);
    expect(fixture.componentInstance.configLoaded).toBe(true);
    expect(fixture.debugElement.query(By.css("router-outlet"))).toBeTruthy();
    expect(fixture.debugElement.query(By.css("#config-error"))).toBeNull();
  });

  it("shows the configuration error when configuration fails to load", () => {
    build(false);
    expect(fixture.componentInstance.configLoaded).toBe(false);
    expect(fixture.debugElement.query(By.css("#config-error"))).toBeTruthy();
    expect(fixture.debugElement.query(By.css("router-outlet"))).toBeNull();
  });
});
