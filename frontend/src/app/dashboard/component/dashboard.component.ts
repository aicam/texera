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

import { Component, NgZone, OnInit, ViewChild } from "@angular/core";
import { UserService } from "../../common/service/user/user.service";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { FlarumService } from "../service/user/flarum/flarum.service";
import { HttpErrorResponse } from "@angular/common/http";
import { ActivatedRoute, NavigationEnd, Router, RouterLink, RouterOutlet } from "@angular/router";
import { HubComponent } from "../../hub/component/hub.component";
import { SocialAuthService, GoogleSigninButtonModule } from "@abacritt/angularx-social-login";
import { AdminSettingsService } from "../service/admin/settings/admin-settings.service";
import { GuiConfigService } from "../../common/service/gui-config.service";

import {
  ABOUT,
  DASHBOARD_ABOUT,
  DASHBOARD_ADMIN_EXECUTION,
  DASHBOARD_ADMIN_GMAIL,
  DASHBOARD_ADMIN_SETTINGS,
  DASHBOARD_ADMIN_USER,
  DASHBOARD_USER_COMPUTING_UNIT,
  DASHBOARD_USER_DATASET,
  DASHBOARD_USER_DISCUSSION,
  DASHBOARD_USER_PROJECT,
  DASHBOARD_USER_QUOTA,
  DASHBOARD_USER_WORKFLOW,
} from "../../app-routing.constant";
import { Version } from "../../../environments/version";
import { SidebarTabs } from "../../common/type/gui-config";
import { User } from "../../common/type/user";
import { Role } from "../../common/type/user";
import { NzLayoutComponent, NzSiderComponent, NzContentComponent } from "ng-zorro-antd/layout";
import { NzMenuDirective, NzSubMenuComponent, NzMenuItemComponent } from "ng-zorro-antd/menu";
import { NgIf } from "@angular/common";
import { ɵNzTransitionPatchDirective } from "ng-zorro-antd/core/transition-patch";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { SearchBarComponent } from "./user/search-bar/search-bar.component";
import { UserIconComponent } from "./user/user-icon/user-icon.component";
import { AgentDockComponent } from "../../workspace/component/agent/agent-dock/agent-dock.component";

@Component({
  selector: "texera-dashboard",
  templateUrl: "dashboard.component.html",
  styleUrls: ["dashboard.component.scss"],
  imports: [
    NzLayoutComponent,
    NzSiderComponent,
    NzMenuDirective,
    NgIf,
    NzSubMenuComponent,
    ɵNzTransitionPatchDirective,
    HubComponent,
    NzMenuItemComponent,
    NzTooltipDirective,
    RouterLink,
    NzIconDirective,
    SearchBarComponent,
    UserIconComponent,
    GoogleSigninButtonModule,
    NzContentComponent,
    RouterOutlet,
    AgentDockComponent,
  ],
})
@UntilDestroy()
export class DashboardComponent implements OnInit {
  @ViewChild(HubComponent) hubComponent!: HubComponent;

  isAdmin: boolean = this.userService.isAdmin();
  isLogin = this.userService.isLogin();
  public gitCommitHash: string = Version.raw;
  displayForum: boolean = true;
  displayNavbar: boolean = true;
  // The docked agent panel shows on dashboard pages only (not the workspace, which
  // has its own floating panel, and not the About hero), and only when enabled.
  showAgentDock: boolean = false;
  isCollapsed: boolean = false;
  showLinks: boolean = false;
  logo: string = "";
  miniLogo: string = "";
  sidebarTabs: SidebarTabs = {
    hub_enabled: false,
    home_enabled: false,
    workflow_enabled: false,
    dataset_enabled: false,
    your_work_enabled: false,
    projects_enabled: false,
    workflows_enabled: false,
    datasets_enabled: false,
    compute_enabled: false,
    cluster_enabled: false,
    quota_enabled: false,
    forum_enabled: false,
    about_enabled: false,
  };

  protected readonly DASHBOARD_USER_PROJECT = DASHBOARD_USER_PROJECT;
  protected readonly DASHBOARD_USER_WORKFLOW = DASHBOARD_USER_WORKFLOW;
  protected readonly DASHBOARD_USER_DATASET = DASHBOARD_USER_DATASET;
  protected readonly DASHBOARD_USER_COMPUTING_UNIT = DASHBOARD_USER_COMPUTING_UNIT;
  protected readonly DASHBOARD_USER_QUOTA = DASHBOARD_USER_QUOTA;
  protected readonly DASHBOARD_USER_DISCUSSION = DASHBOARD_USER_DISCUSSION;
  protected readonly DASHBOARD_ADMIN_USER = DASHBOARD_ADMIN_USER;
  protected readonly DASHBOARD_ADMIN_GMAIL = DASHBOARD_ADMIN_GMAIL;
  protected readonly DASHBOARD_ADMIN_EXECUTION = DASHBOARD_ADMIN_EXECUTION;
  protected readonly DASHBOARD_ADMIN_SETTINGS = DASHBOARD_ADMIN_SETTINGS;

  constructor(
    private userService: UserService,
    private router: Router,
    private flarumService: FlarumService,
    private ngZone: NgZone,
    private socialAuthService: SocialAuthService,
    private route: ActivatedRoute,
    private adminSettingsService: AdminSettingsService,
    protected config: GuiConfigService
  ) {}

  ngOnInit(): void {
    // Collapse the sidebar on the landing/about page so the hero animation
    // owns the frame; expand it everywhere else.
    this.isCollapsed = this.isAboutPage(this.router.url);

    this.router.events.pipe(untilDestroyed(this)).subscribe(() => {
      this.checkRoute();
    });

    this.router.events.pipe(untilDestroyed(this)).subscribe(event => {
      if (event instanceof NavigationEnd) {
        this.checkRoute();
        this.showLinks = this.isAboutPage(event.url);
        this.isCollapsed = this.isAboutPage(event.url);
      }
    });

    this.userService
      .userChanged()
      .pipe(untilDestroyed(this))
      .subscribe(user => {
        this.ngZone.run(() => {
          this.isLogin = this.userService.isLogin();
          this.isAdmin = this.userService.isAdmin();
          this.forumLogin();
        });
      });

    this.socialAuthService.authState.pipe(untilDestroyed(this)).subscribe(user => {
      // authState is a ReplaySubject and re-emits the cached user every time
      // this component mounts. Skip when we already have a JWT (the user
      // navigated here from elsewhere) or when signOut() emits null — only
      // act on a fresh Google sign-in.
      if (!user || this.userService.isLogin()) return;
      this.userService
        .googleLogin(user.idToken)
        .pipe(untilDestroyed(this))
        .subscribe(() => {
          this.ngZone.run(() => {
            this.router.navigateByUrl(this.route.snapshot.queryParams["returnUrl"] || DASHBOARD_USER_WORKFLOW);
          });
        });
    });

    this.loadLogos();

    this.loadTabs();

    // Compute initial chrome state in case the first navigation fired before the
    // router-events subscription above was attached.
    this.checkRoute();
  }

  loadLogos(): void {
    this.adminSettingsService
      .getSetting("logo")
      .pipe(untilDestroyed(this))
      .subscribe(dataUri => {
        this.logo = dataUri;
      });

    this.adminSettingsService
      .getSetting("mini_logo")
      .pipe(untilDestroyed(this))
      .subscribe(dataUri => {
        this.miniLogo = dataUri;
      });

    this.adminSettingsService
      .getSetting("favicon")
      .pipe(untilDestroyed(this))
      .subscribe(dataUri => {
        document.querySelectorAll("link[rel*='icon']").forEach(el => ((el as HTMLLinkElement).href = dataUri));
      });
  }

  loadTabs(): void {
    (Object.keys(this.sidebarTabs) as (keyof SidebarTabs)[]).forEach(tab => {
      this.adminSettingsService
        .getSetting(tab)
        .pipe(untilDestroyed(this))
        .subscribe(value => {
          this.sidebarTabs[tab] = value === "true";
        });
    });
  }

  forumLogin() {
    if (!document.cookie.includes("flarum_remember") && this.isLogin) {
      this.flarumService
        .auth()
        .pipe(untilDestroyed(this))
        .subscribe({
          next: (response: any) => {
            document.cookie = `flarum_remember=${response.token};path=/`;
          },
          error: (err: unknown) => {
            if ([404, 500].includes((err as HttpErrorResponse).status)) {
              this.displayForum = false;
            } else {
              this.flarumService
                .register()
                .pipe(untilDestroyed(this))
                .subscribe(() => this.forumLogin());
            }
          },
        });
    }
  }

  checkRoute() {
    const currentRoute = this.router.url;
    this.displayNavbar = this.isNavbarEnabled(currentRoute);
    this.showAgentDock = this.copilotEnabled && !this.isWorkspacePage(currentRoute) && !this.isAboutPage(currentRoute);
  }

  private get copilotEnabled(): boolean {
    try {
      return this.config.env.copilotEnabled;
    } catch {
      return false;
    }
  }

  private isWorkspacePage(url: string): boolean {
    return /\/dashboard\/user\/workflow\/\d+/.test(url);
  }

  isNavbarEnabled(currentRoute: string) {
    // Hide navbar for workflow workspace pages (with numeric ID)
    if (currentRoute.match(/\/dashboard\/user\/workflow\/\d+/)) {
      return false;
    }
    // About page owns the full-height hero; auth controls move into the
    // hero corner so the page doesn't surrender 70px to the search bar.
    if (this.isAboutPage(currentRoute)) {
      return false;
    }
    // The standalone /about feature page is immersive (its own hero +
    // animated backdrop), so drop the search-bar navbar there too. The
    // sidebar stays expanded so the page is still navigable.
    if (this.isAboutContentPage(currentRoute)) {
      return false;
    }
    return true;
  }

  // The standalone About feature page at /about (distinct from the landing
  // hero at "/"). Kept separate from isAboutPage so it does NOT collapse the
  // sidebar — only the navbar is hidden.
  private isAboutContentPage(url: string): boolean {
    return url === ABOUT || url.startsWith(`${ABOUT}?`) || url.startsWith(`${ABOUT}#`);
  }

  // The About / landing page now lives at "/" (with a legacy redirect from
  // /dashboard/about), so detect both forms when toggling UI affordances.
  private isAboutPage(url: string): boolean {
    return url === "/" || url.startsWith("/?") || url.startsWith("/dashboard/about");
  }

  handleCollapseChange(collapsed: boolean) {
    this.isCollapsed = collapsed;
    const resizeEvent = new Event("resize");
    const editor = document.getElementById("workflow-editor");
    if (editor) {
      setTimeout(() => {
        window.dispatchEvent(resizeEvent);
      }, 175);
    }
  }

  protected readonly DASHBOARD_ABOUT = DASHBOARD_ABOUT;
  protected readonly ABOUT = ABOUT;
  protected readonly String = String;
}
