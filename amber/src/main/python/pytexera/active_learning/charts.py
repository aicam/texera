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

"""A learning curve that redraws on every new row, so it is watched while training runs."""

from typing import Dict, List

import plotly.graph_objects as go
import plotly.io as pio

COLORS = ["#7a7f87", "#7c3aed", "#16a9c0", "#eb6834"]


def learning_curve_html(rows: List[Dict[str, object]], x: str, ys: List[str], title: str) -> str:
    fig = go.Figure()
    for index, y in enumerate(ys):
        points = [(row[x], row[y]) for row in rows if row.get(x) is not None and row.get(y) is not None]
        fig.add_trace(
            go.Scatter(
                x=[p[0] for p in points],
                y=[p[1] for p in points],
                mode="lines+markers",
                name=y.replace("_", " "),
                line={"color": COLORS[index % len(COLORS)], "width": 3},
            )
        )
    fig.update_layout(
        title=title,
        xaxis_title=x.replace("_", " "),
        template="plotly_white",
        legend={"orientation": "h", "y": -0.2},
        margin={"l": 50, "r": 20, "t": 50, "b": 50},
    )
    return pio.to_html(fig, include_plotlyjs="cdn", full_html=False)
