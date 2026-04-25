import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { ReputationPoint } from "../features/types";

type Props = {
  data: ReputationPoint[];
};

export function ReputationChart({ data }: Props) {
  return (
    <div className="chart-frame" data-testid="reputation-chart">
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 18, right: 20, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id="scoreFill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="5%" stopColor="#e95d75" stopOpacity={0.45} />
              <stop offset="95%" stopColor="#e95d75" stopOpacity={0.04} />
            </linearGradient>
          </defs>
          <XAxis dataKey="label" tickLine={false} axisLine={false} />
          <YAxis domain={[3, 5]} tickLine={false} axisLine={false} />
          <Tooltip />
          <Area
            dataKey="average_score"
            type="monotone"
            stroke="#e95d75"
            fill="url(#scoreFill)"
            strokeWidth={3}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
