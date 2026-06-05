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

import { AfterViewInit, Component, ElementRef, OnDestroy, OnInit, QueryList, ViewChildren } from "@angular/core";
import { Router } from "@angular/router";
import { NgFor, NgIf, NgClass, AsyncPipe } from "@angular/common";
import { BehaviorSubject } from "rxjs";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { GoogleSigninButtonModule } from "@abacritt/angularx-social-login";
import { UserService } from "src/app/common/service/user/user.service";
import { GuiConfigService } from "../../../common/service/gui-config.service";
import { DASHBOARD_USER_WORKFLOW } from "../../../app-routing.constant";

interface Mote {
  x: number; // % from left
  y: number; // % from top
  dx: number; // px horizontal drift over lifetime
  dur: number; // s
  delay: number; // s
}

interface Feature {
  eyebrow: string; // small uppercase kicker
  title: string;
  body: string;
  image: string; // path under /assets
  alt: string;
  accent: "cyan" | "magenta";
}

// The About page tells the dkNET-AI story as a vertical "data pipeline":
// each capability is a node on a glowing spine that lights up as the reader
// scrolls, echoing the dataflow-editor metaphor at the heart of the platform.
// Content + screenshots come from src/assets/about/content.txt (authored by
// the dkNET team); keep this list in sync with that file.
@UntilDestroy()
@Component({
  selector: "texera-about-page",
  templateUrl: "./about-page.component.html",
  styleUrls: ["./about-page.component.scss"],
  imports: [NgFor, NgIf, NgClass, AsyncPipe, GoogleSigninButtonModule],
})
export class AboutPageComponent implements OnInit, AfterViewInit, OnDestroy {
  @ViewChildren("reveal") revealEls!: QueryList<ElementRef<HTMLElement>>;

  // Drives the CTA: signed-out users get the Google sign-in button (so a click
  // opens the Google login directly); signed-in users get a plain button that
  // jumps straight into their workflows.
  readonly isLogin$ = new BehaviorSubject<boolean>(false);

  readonly features: Feature[] = [
    {
      eyebrow: "AI Assistants",
      title: "AI agents for data science using visual dataflows",
      body:
        "Get help building and debugging workflows from an in-platform AI assistant that can suggest " +
        "operators, write Python and R code, explain results, and query biomedical databases and tools.",
      image: "assets/about/workflow_chatbot.png",
      alt: "dkNET-AI workflow editor with the in-platform AI assistant suggesting operators",
      accent: "cyan",
    },
    {
      eyebrow: "Elastic Compute",
      title: "Computing resources on a need basis",
      body:
        "Request dedicated computing power to run your analyses on demand, scaling up for larger " +
        "datasets or more demanding tasks.",
      image: "assets/about/computing_unit.png",
      alt: "Computing unit selection panel for provisioning on-demand compute",
      accent: "magenta",
    },
    {
      eyebrow: "Scalable Alignment",
      title: "CloudBioMapper for sequence alignment",
      body:
        "Run sequence-alignment tasks faster by launching on-demand clusters on the cloud and aligning " +
        "in parallel with pay-as-you-go scaling.",
      image: "assets/about/cloudbiomapper.png",
      alt: "CloudBioMapper launching on-demand cloud clusters for parallel sequence alignment",
      accent: "cyan",
    },
    {
      eyebrow: "Guided Analysis",
      title: "Single-cell RNA sequencing analysis",
      body:
        "Follow a complete, guided example of taking a single-cell RNA-seq dataset from raw data through " +
        "analysis to results, entirely in the GUI-based workflow editor.",
      image: "assets/about/R_udf.png",
      alt: "Single-cell RNA-seq analysis built with R user-defined functions in the workflow editor",
      accent: "magenta",
    },
  ];

  // Drifting illuminated motes — data dust caught in the network's glow.
  // Generated once so each visit has fresh placement but no scroll jitter.
  readonly motes: Mote[] = Array.from({ length: 22 }, () => ({
    x: Math.random() * 100,
    y: 75 + Math.random() * 35,
    dx: (Math.random() - 0.5) * 120,
    dur: 16 + Math.random() * 14,
    delay: -Math.random() * 22,
  }));

  private observer?: IntersectionObserver;

  constructor(
    private router: Router,
    private userService: UserService,
    private host: ElementRef<HTMLElement>,
    protected config: GuiConfigService
  ) {}

  ngOnInit(): void {
    this.isLogin$.next(this.userService.isLogin());
    this.userService
      .userChanged()
      .pipe(untilDestroyed(this))
      .subscribe(user => this.isLogin$.next(user !== undefined));
  }

  ngAfterViewInit(): void {
    // Scroll-reveal: add `.is-visible` the first time each element enters the
    // viewport so headings, cards and screenshots fade/slide in on the way down.
    if (typeof IntersectionObserver === "undefined") {
      this.revealEls.forEach(el => el.nativeElement.classList.add("is-visible"));
      return;
    }
    this.observer = new IntersectionObserver(
      entries => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            this.observer?.unobserve(entry.target);
          }
        }
      },
      { root: this.host.nativeElement, threshold: 0.18, rootMargin: "0px 0px -8% 0px" }
    );
    this.revealEls.forEach(el => this.observer!.observe(el.nativeElement));
  }

  ngOnDestroy(): void {
    this.observer?.disconnect();
  }

  // Only wired to the signed-in CTA. Signed-out users click the Google button
  // instead (its login is handled by the parent DashboardComponent's authState
  // subscription, which redirects to the workflows page once the JWT is issued).
  getStarted(): void {
    this.router.navigate([DASHBOARD_USER_WORKFLOW]);
  }
}
