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

const BYTES_PER_UNIT = 1024;

/**
 * Format upload speed
 */
export const formatSpeed = (bytesPerSecond = 0) => {
  if (bytesPerSecond <= 0) return "0.0 MB/s";

  const mbps = bytesPerSecond / (BYTES_PER_UNIT * BYTES_PER_UNIT);
  return `${mbps.toFixed(1)} MB/s`;
};

/**
 * Format time duration
 */
export const formatTime = (seconds?: number): string => {
  if (!seconds || seconds <= 0) return "1s";
  const s = Math.max(1, Math.round(seconds));

  // Under 1 minute: show seconds only
  if (s < 60) {
    return `${s}s`;
  }

  // Under 1 hour: show minutes (and seconds if not zero)
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return sec === 0 ? `${m}m` : `${m}m${sec.toString().padStart(2, "0")}s`;
  }

  // 1 hour+: show hours (and minutes if not zero)
  const h = Math.floor(s / 3600);
  const min = Math.floor((s % 3600) / 60);

  return min === 0 ? `${h}h` : `${h}h${min}m`;
};

/**
 * Format a past timestamp as a relative time string (e.g. "5 minutes ago").
 * Falls back to an absolute date once the timestamp is older than ~4 weeks.
 */
export const formatRelativeTime = (timestamp: number | undefined): string => {
  if (timestamp === undefined) {
    return "Unknown";
  }

  // count + unit with correct pluralization, e.g. relativeAgo(1, "minute") -> "1 minute ago"
  const relativeAgo = (count: number, unit: string): string => `${count} ${unit}${count === 1 ? "" : "s"} ago`;

  const minutesAgo = Math.floor((new Date().getTime() - timestamp) / (1000 * 60));
  const hoursAgo = Math.floor(minutesAgo / 60);
  const daysAgo = Math.floor(hoursAgo / 24);
  const weeksAgo = Math.floor(daysAgo / 7);

  if (minutesAgo < 60) return relativeAgo(minutesAgo, "minute");
  if (hoursAgo < 24) return relativeAgo(hoursAgo, "hour");
  if (daysAgo < 7) return relativeAgo(daysAgo, "day");
  if (weeksAgo < 4) return relativeAgo(weeksAgo, "week");
  return new Date(timestamp).toLocaleDateString();
};

/**
 * Format a count, abbreviating values >= 1000 (e.g. 1500 -> "1.5k").
 */
export const formatCount = (count: number): string => {
  if (count >= 1000) {
    return (count / 1000).toFixed(1) + "k";
  }
  return count.toString();
};
