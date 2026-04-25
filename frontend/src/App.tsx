import {
  Bell,
  CalendarDays,
  CheckCircle2,
  Flame,
  Gift,
  MapPin,
  MessageCircle,
  Search,
  ShieldCheck,
  Sparkles,
  Trophy,
} from "lucide-react";
import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";

import { brand } from "./app/config";
import type { AppDispatch, RootState } from "./app/store";
import { BadgePill } from "./components/BadgePill";
import { MostViewedTable } from "./components/MostViewedTable";
import { ProgressBar } from "./components/ProgressBar";
import { ReputationChart } from "./components/ReputationChart";
import { loadDashboard, setFetish, setMinScore, setUserType } from "./features/swinraSlice";

export function App() {
  const dispatch = useDispatch<AppDispatch>();
  const { data, filters, status } = useSelector((state: RootState) => state.swinra);

  useEffect(() => {
    dispatch(loadDashboard());
  }, [dispatch]);

  if (!data) {
    return <main className="loading-shell">{status === "error" ? "No se pudo cargar Swinra" : "Cargando Swinra"}</main>;
  }

  const filteredMatches = data.matches.filter((profile) => {
    const scoreMatch = profile.average_score >= filters.minScore;
    const typeMatch = filters.userType === "all" || profile.user_type === filters.userType;
    const fetishMatch = !filters.fetish || profile.fetishes.includes(filters.fetish);
    return scoreMatch && typeMatch && fetishMatch;
  });

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Web MVP</p>
          <h1>{brand.name}</h1>
        </div>
        <p>{brand.tagline}</p>
      </header>

      <section className="hero-band">
        <div className="profile-summary">
          <div className="avatar-mark">{data.profile.display_name.slice(0, 2)}</div>
          <div>
            <div className="identity-row">
              <h2>{data.profile.display_name}</h2>
              {data.profile.is_verified && <ShieldCheck aria-label="Perfil verificado" size={22} />}
            </div>
            <p>{data.profile.headline}</p>
            <div className="meta-row">
              <span>
                <MapPin size={16} /> {data.profile.location}
              </span>
              <span>
                <Flame size={16} /> {data.profile.reputation_level}
              </span>
            </div>
          </div>
        </div>
        <div className="score-orbit">
          <span>{data.profile.average_score.toFixed(1)}</span>
          <small>Scoring Fira</small>
        </div>
      </section>

      <section className="metric-grid">
        <article className="panel metric">
          <CheckCircle2 size={24} />
          <span>{data.profile.profile_progress}%</span>
          <p>Perfil completo</p>
        </article>
        <article className="panel metric">
          <Trophy size={24} />
          <span>{data.analytics.reputation_percentile}</span>
          <p>Percentil reputacion</p>
        </article>
        <article className="panel metric">
          <Gift size={24} />
          <span>{data.analytics.gifts_sent}</span>
          <p>Regalos enviados</p>
        </article>
        <article className="panel metric">
          <Bell size={24} />
          <span>{data.analytics.views}</span>
          <p>Visualizaciones</p>
        </article>
      </section>

      <section className="content-grid">
        <section className="panel main-panel">
          <div className="panel-title">
            <div>
              <p className="eyebrow">Reputacion</p>
              <h2>Evolucion mensual</h2>
            </div>
            <Sparkles size={22} />
          </div>
          <ReputationChart data={data.reputation} />
          <ProgressBar value={data.profile.profile_progress} label="Completitud del perfil" />
          <div className="badge-list">
            {data.profile.badges.map((badge) => (
              <BadgePill badge={badge} key={badge.code} />
            ))}
          </div>
        </section>

        <MostViewedTable rows={data.mostViewed} isPremium={data.profile.is_premium} />
      </section>

      <section className="content-grid">
        <section className="panel">
          <div className="panel-title">
            <div>
              <p className="eyebrow">Matching</p>
              <h2>Busqueda avanzada</h2>
            </div>
            <Search size={22} />
          </div>
          <div className="filters" data-testid="matching-filters">
            <label>
              Puntuacion minima
              <input
                max="5"
                min="0"
                step="0.1"
                type="range"
                value={filters.minScore}
                onChange={(event) => dispatch(setMinScore(Number(event.target.value)))}
              />
              <strong>{filters.minScore.toFixed(1)}</strong>
            </label>
            <label>
              Tipo
              <select
                value={filters.userType}
                onChange={(event) => dispatch(setUserType(event.target.value as "all" | "couple" | "single"))}
              >
                <option value="all">Todos</option>
                <option value="couple">Parejas</option>
                <option value="single">Solteros</option>
              </select>
            </label>
            <label>
              Fetiche
              <select value={filters.fetish} onChange={(event) => dispatch(setFetish(event.target.value))}>
                <option value="">Todos</option>
                <option value="roleplay">Roleplay</option>
                <option value="lingerie">Lingerie</option>
                <option value="wellness">Wellness</option>
              </select>
            </label>
          </div>
          <div className="match-list">
            {filteredMatches.map((profile) => (
              <article className="match-card" key={profile.id}>
                <div>
                  <h3>{profile.display_name}</h3>
                  <p>{profile.location} · {profile.user_type === "couple" ? "Pareja" : "Soltero"}</p>
                </div>
                <strong>{profile.average_score.toFixed(1)}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-title">
            <div>
              <p className="eyebrow">Comunidad</p>
              <h2>Foros y eventos</h2>
            </div>
            <MessageCircle size={22} />
          </div>
          <div className="stack-list">
            {data.forumPosts.map((post) => (
              <article className="list-item" key={post.id}>
                <span>{post.topic}</span>
                <h3>{post.title}</h3>
                <p>{post.points} puntos · {post.replies} respuestas</p>
              </article>
            ))}
            {data.events.map((event) => (
              <article className="list-item event-item" key={event.id}>
                <span>
                  <CalendarDays size={16} /> {event.mode === "virtual" ? "Virtual" : "Presencial"}
                </span>
                <h3>{event.title}</h3>
                <p>{event.rsvp_count} RSVP</p>
              </article>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}
