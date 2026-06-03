# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

FROM oven/bun:1-alpine

WORKDIR /app

COPY bio-mcp-service/package.json bio-mcp-service/bun.lock ./

RUN bun install --frozen-lockfile --production

COPY bio-mcp-service/src ./src
COPY bio-mcp-service/tsconfig.json ./

COPY LICENSE ./LICENSE
COPY NOTICE ./NOTICE
COPY DISCLAIMER ./DISCLAIMER
COPY licenses ./licenses

RUN addgroup -S -g 1001 texera \
 && adduser -S -u 1001 -G texera -h /app texera \
 && chown -R texera:texera /app
USER texera

EXPOSE 3010

CMD ["bun", "run", "src/index.ts"]
