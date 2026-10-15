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

# Compare models: validation Dice of the plain U-Net (newest weights, as MONAI Label
# serves them) and of the U-Net with weight averaging, by how many labels each had.
# Input 0 is the plain U-Net's epochs, input 1 the averaging model's rounds. The chart
# is redrawn with every row, so it is current while the workflow keeps running.
from pytexera import *

import plotly.graph_objects as go
import plotly.io as pio

PLAIN, AVERAGED = "#8a8f98", "#7c3aed"


class CompareModels(UDFOperatorV2):
    def open(self) -> None:
        # labeled cases -> the newest Dice reported with that many labels
        self.plain, self.averaged = {}, {}

    @overrides
    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
        row = tuple_.as_dict()
        if port == 0:
            self.plain[row["labeled_cases"]] = row["validation_dice"]
        else:
            self.averaged[row["labeled_cases"]] = row["averaged_dice"]
        yield {"html-content": self.chart()}

    def chart(self) -> str:
        fig = go.Figure()
        for name, points, color in (
            ("U-Net, newest weights", self.plain, PLAIN),
            ("U-Net, weight averaging", self.averaged, AVERAGED),
        ):
            xs = sorted(points)
            fig.add_trace(go.Scatter(x=xs, y=[points[x] for x in xs], name=name, mode="lines+markers",
                                     line={"color": color, "width": 3}))
        title = "Validation Dice by number of labels"
        if self.averaged:
            x = max(self.averaged)
            before = [n for n in self.plain if n <= x]
            if before:
                plain = self.plain[max(before)]
                gain = self.averaged[x] - plain
                title += (f"<br><sup>With {x} labels: weight averaging {self.averaged[x]:.3f}, "
                          f"newest weights {plain:.3f} ({gain:+.3f})</sup>")
        fig.update_layout(title=title, xaxis_title="labeled cases", yaxis_title="validation Dice",
                          template="plotly_white", legend={"orientation": "h", "y": -0.25},
                          margin={"l": 60, "r": 20, "t": 70, "b": 60})
        return pio.to_html(fig, include_plotlyjs="cdn", full_html=False)
