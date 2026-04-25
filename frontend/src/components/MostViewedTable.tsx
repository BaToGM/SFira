import { Lock, Star } from "lucide-react";

import type { MostViewedCouple } from "../features/types";

type Props = {
  rows: MostViewedCouple[];
  isPremium: boolean;
};

export function MostViewedTable({ rows, isPremium }: Props) {
  if (!isPremium) {
    return (
      <section className="panel premium-locked" data-testid="premium-locked">
        <Lock size={22} />
        <div>
          <h2>Pareja mas vista</h2>
          <p>Disponible para usuarios premium con estadisticas avanzadas.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel" data-testid="most-viewed-widget">
      <div className="panel-title">
        <div>
          <p className="eyebrow">Premium en tiempo real</p>
          <h2>Pareja mas vista</h2>
        </div>
        <Star size={22} />
      </div>
      <div className="table">
        <div className="table-row table-head">
          <span>Nombre</span>
          <span>Puntuacion</span>
          <span>Visitas</span>
          <span>Badge</span>
        </div>
        {rows.map((row) => (
          <div className="table-row" key={row.couple_name}>
            <strong>{row.couple_name}</strong>
            <span>{row.average_score.toFixed(1)}</span>
            <span>{row.visits}</span>
            <span>{row.current_badge}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
