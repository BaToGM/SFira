import {
  Bell,
  Camera,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Eye,
  Flame,
  Gift,
  HeartHandshake,
  Lock,
  MapPin,
  MessageCircle,
  MessageSquareQuote,
  Radar,
  Search,
  ShieldCheck,
  Sparkles,
  Star,
  Trophy,
  Users,
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
import type { Profile } from "./features/types";

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
  const primaryPhoto = (profile: Profile) => (profile.photos ?? []).find((photo) => photo.is_primary) ?? profile.photos?.[0];
  const profilePublicPhotos = (data.profile.photos ?? []).filter((photo) => photo.visibility === "public");
  const privatePhotoCount = (data.profile.photos ?? []).filter((photo) => photo.visibility === "private").length;
  const featuredReviews = (data.profile.reviews ?? []).slice(0, 2);

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand-lockup" href="#inicio" aria-label="Inicio Swinra">
          <span className="brand-mark">S</span>
          <span>{brand.name}</span>
        </a>
        <nav className="nav-links" aria-label="Navegacion principal">
          <a href="#dashboard">Dashboard</a>
          <a href="#matching">Matching</a>
          <a href="#comunidad">Comunidad</a>
          <a href="#premium">Premium</a>
        </nav>
      </header>

      <section className="home-hero" id="inicio">
        <div className="hero-copy">
          <p className="eyebrow">Web MVP para comunidad privada</p>
          <h1>{brand.name}</h1>
          <p>{brand.tagline}. Matching, reputacion, eventos y premium en una experiencia lista para presentar.</p>
          <div className="hero-actions">
            <a className="primary-action" href="#matching">
              Explorar perfiles <ChevronRight size={18} />
            </a>
            <a className="secondary-action" href="#dashboard">Ver dashboard</a>
          </div>
        </div>
        <div className="hero-product" aria-label="Resumen del producto">
          <div className="product-card primary-product-card">
            <span>Scoring Fira</span>
            <strong>{data.profile.average_score.toFixed(1)}</strong>
            <p>Reputacion media visible antes de conectar.</p>
          </div>
          <div className="product-card">
            <span>Perfiles filtrados</span>
            <strong>{filteredMatches.length}</strong>
            <p>Solo perfiles por encima del umbral configurado.</p>
          </div>
          <div className="product-card">
            <span>Perfil mas visto</span>
            <strong>{data.mostViewed[0]?.visits ?? 0}</strong>
            <p>Senal premium para descubrir perfiles con traccion.</p>
          </div>
        </div>
      </section>

      <section className="feature-strip" aria-label="Capacidades principales">
        <article>
          <ShieldCheck size={22} />
          <h2>Confianza</h2>
          <p>Verificacion opcional, badges y niveles de reputacion.</p>
        </article>
        <article>
          <Radar size={22} />
          <h2>Descubrimiento</h2>
          <p>Filtros por puntuacion, tipo, ubicacion, intereses y fetiches.</p>
        </article>
        <article>
          <Users size={22} />
          <h2>Comunidad</h2>
          <p>Foros, eventos, RSVP y ranking mensual de actividad.</p>
        </article>
        <article>
          <Star size={22} />
          <h2>Premium</h2>
          <p>Hotlists, super-puntuaciones, regalos y estadisticas.</p>
        </article>
      </section>

      <section className="hero-band" id="dashboard">
        <div className="profile-summary">
          <div className="profile-photo-frame">
            {primaryPhoto(data.profile) ? (
              <img src={primaryPhoto(data.profile)?.url} alt={primaryPhoto(data.profile)?.alt} />
            ) : (
              <span>{data.profile.display_name.slice(0, 2)}</span>
            )}
          </div>
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
              <span>
                <HeartHandshake size={16} /> {data.profile.user_type === "couple" ? "Pareja" : "Soltero"}
              </span>
              <span>
                <Camera size={16} /> {profilePublicPhotos.length} fotos publicas
              </span>
            </div>
          </div>
        </div>
        <div className="score-orbit">
          <span>{data.profile.average_score.toFixed(1)}</span>
          <small>Scoring Fira</small>
        </div>
      </section>

      <section className="profile-showcase" aria-label="Perfil con fotos y confianza">
        <article className="panel photo-gallery-panel">
          <div className="panel-title">
            <div>
              <p className="eyebrow">Perfil visual</p>
              <h2>Fotos y album privado</h2>
            </div>
            <Camera size={22} />
          </div>
          <div className="photo-gallery">
            {profilePublicPhotos.map((photo) => (
              <img src={photo.url} alt={photo.alt} key={photo.id} />
            ))}
            <div className="private-album-tile">
              <Lock size={22} />
              <strong>{privatePhotoCount}</strong>
              <span>privada bajo permiso</span>
            </div>
          </div>
          <p className="privacy-note">
            Las fotos publicas ayudan a decidir si iniciar conversacion; el album privado queda bajo solicitud y
            consentimiento.
          </p>
        </article>

        <article className="panel review-panel">
          <div className="panel-title">
            <div>
              <p className="eyebrow">Confianza social</p>
              <h2>Resenas verificadas</h2>
            </div>
            <MessageSquareQuote size={22} />
          </div>
          <div className="review-list">
            {featuredReviews.map((review) => (
              <article className="review-item" key={review.id}>
                <div className="row-between">
                  <strong>{review.author}</strong>
                  <span>{review.score.toFixed(1)}</span>
                </div>
                <p>{review.comment}</p>
                <small>{review.is_verified_interaction ? "Interaccion verificada" : "Pendiente de moderacion"}</small>
              </article>
            ))}
          </div>
        </article>
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

      <section className="content-grid" id="premium">
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
              <h2 id="matching">Busqueda avanzada</h2>
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
                <div className="match-photo">
                  {primaryPhoto(profile) ? (
                    <img src={primaryPhoto(profile)?.url} alt={primaryPhoto(profile)?.alt} />
                  ) : (
                    <span>{profile.display_name.slice(0, 2)}</span>
                  )}
                </div>
                <div>
                  <h3>{profile.display_name}</h3>
                  <p>{profile.headline}</p>
                  <span>
                    {profile.location} - {profile.user_type === "couple" ? "Pareja" : "Soltero"}
                  </span>
                  <small>
                    <Eye size={14} /> {profile.photos?.filter((photo) => photo.visibility === "public").length ?? 0} fotos
                    visibles
                  </small>
                </div>
                <strong>{profile.average_score.toFixed(1)}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="panel" id="comunidad">
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
                <p>{post.points} puntos - {post.replies} respuestas</p>
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

      <section className="recommendation-band">
        <div>
          <p className="eyebrow">Feature recomendada</p>
          <h2>Circulos de confianza</h2>
          <p>
            Una capa para compartir fotos privadas, ubicacion aproximada y disponibilidad solo con usuarios validados o
            con interacciones previas. Es una funcion premium natural y reduce friccion sin comprometer privacidad.
          </p>
        </div>
        <a className="secondary-action" href="#matching">Ver perfiles compatibles</a>
      </section>

      <section className="journey-band">
        <div>
          <p className="eyebrow">Flujo de usuario</p>
          <h2>De registro a encuentro con reputacion</h2>
        </div>
        <div className="journey-steps">
          <article>
            <span>01</span>
            <h3>Perfil</h3>
            <p>Registro como pareja o soltero, intereses, preferencias y barra de completitud.</p>
          </article>
          <article>
            <span>02</span>
            <h3>Matching</h3>
            <p>Busqueda filtrada por score minimo, orientacion, fetiches, tipo y ubicacion.</p>
          </article>
          <article>
            <span>03</span>
            <h3>Interaccion</h3>
            <p>Chat, encuentro virtual o presencial con puntuacion posterior.</p>
          </article>
          <article>
            <span>04</span>
            <h3>Reputacion</h3>
            <p>Badges, ranking, hotlists y analitica premium para perfiles destacados.</p>
          </article>
        </div>
      </section>
    </main>
  );
}
