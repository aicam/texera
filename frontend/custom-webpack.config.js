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

const { LicenseWebpackPlugin } = require("license-webpack-plugin");
const { resolve } = require("path");

const monacoDefaultExtensionLicenseText = `MIT License

Copyright (c) CodinGame

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

const licenseTextOverrides = {
  "@codingame/monaco-vscode-python-default-extension": monacoDefaultExtensionLicenseText,
  "@codingame/monaco-vscode-r-default-extension": monacoDefaultExtensionLicenseText,
};

module.exports = {
  module: {
    rules: [
      {
        test: /\.css$/,
        use: ["style-loader", "css-loader"],
        include: [
          resolve(__dirname, "node_modules/monaco-editor"),
          resolve(__dirname, "node_modules/monaco-breakpoints"),
        ],
      },
    ],
    // Enable URL handling in webpack's JavaScript parser, required for loading .wasm files.
    // See https://github.com/angular/angular-cli/issues/24617
    parser: {
      javascript: {
        url: true,
      },
    },
  },
  plugins: [
    new LicenseWebpackPlugin({
      perChunkOutput: false,
      outputFilename: "3rdpartylicenses.json",
      licenseTextOverrides,
      renderLicenses: modules =>
        JSON.stringify(
          modules
            .map(m => ({
              name: m.packageJson && m.packageJson.name,
              version: m.packageJson && m.packageJson.version,
              license: m.licenseId,
            }))
            .filter(e => e.name && e.version)
            .sort((a, b) => (a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name))),
          null,
          2
        ),
    }),
  ],
};
