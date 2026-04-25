import {
  BarChart3,
  Bell,
  Bookmark,
  Camera,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Coins,
  Crown,
  Eye,
  Flame,
  Gift,
  HeartHandshake,
  Lock,
  LogIn,
  MapPin,
  MessageCircle,
  MessageSquareQuote,
  Plus,
  Radar,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  Star,
  Trophy,
  UserPlus,
  Users,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import type { FormEvent } from "react";

import { brand } from "./app/config";
import type { AppDispatch, RootState } from "./app/store";
import { BadgePill } from "./components/BadgePill";
import { MostViewedTable } from "./components/MostViewedTable";
import { ProgressBar } from "./components/ProgressBar";
import { ReputationChart } from "./components/ReputationChart";
import { loadDashboard, setFetish, setMinScore, setUserType } from "./features/swinraSlice";
import type { Profile } from "./features/types";

type View = "inicio" | "dashboard" | "matching" | "comunidad" | "premium" | "creditos" | "acceso";

const validViews: View[] = ["inicio", "dashboard", "matching", "comunidad", "premium", "creditos", "acceso"];

const viewFromHash = (): View => {
  const hash = window.location.hash.replace("#", "") as View;
  return validViews.includes(hash) ? hash : "inicio";
};

export function App() {
  const dispatch = useDispatch<AppDispatch>();
  const { data, filters, status } = useSelector((state: RootState) => state.swinra);
  const [view, setView] = useState<View>(viewFromHash);
  const [savedSearches, setSavedSearches] = useState(1);
  const [hotlistSaved, setHotlistSaved] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [communityComposer, setCommunityComposer] = useState<"post" | "event" | null>(null);
  const [credits, setCredits] = useState(420);
  const [redeemedReward, setRedeemedReward] = useState("");
  const [accessMessage, setAccessMessage] = useState("Sesion demo activa: Luna & Marco");
  const monthlyPoints = useMemo(
    () => [
      { label: "Perfil completo", points: 120, icon: CheckCircle2 },
      { label: "Resena verificada", points: 80, icon: MessageSquareQuote },
      { label: "RSVP a evento", points: 40, icon: CalendarDays },
      { label: "Aporte en foro", points: 25, icon: MessageCircle },
    ],
    [],
  );

  useEffect(() => {
    dispatch(loadDashboard());
  }, [dispatch]);

  useEffect(() => {
    const onHashChange = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHashChange);
    onHashChange();
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  if (!data) {
    return <main className="loading-shell">{status === "error" ? "No se pudo cargar Swinra" : "Cargando Swinra"}</main>;
  }

  const primaryPhoto = (profile: Profile) => (profile.photos ?? []).find((photo) => photo.is_primary) ?? profile.photos?.[0];
  const profilePublicPhotos = (data.profile.photos ?? []).filter((photo) => photo.visibility === "public");
  const privatePhotoCount = (data.profile.photos ?? []).filter((photo) => photo.visibility === "private").length;
  const featuredReviews = (data.profile.reviews ?? []).slice(0, 2);
  const filteredMatches = data.matches.filter((profile) => {
    const scoreMatch = profile.average_score >= filters.minScore;
    const typeMatch = filters.userType === "all" || profile.user_type === filters.userType;
    const fetishMatch = !filters.fetish || profile.fetishes.includes(filters.fetish);
    return scoreMatch && typeMatch && fetishMatch;
  });
  const rewards = [
    { name: "Regalo virtual privado", cost: 90, icon: Gift },
    { name: "Super-puntuacion", cost: 140, icon: Star },
    { name: "Banner premium 7 dias", cost: 220, icon: Crown },
  ];

  const navigate = (target: View) => {
    window.location.hash = target;
    setView(target);
  };

  const saveSearch = () => setSavedSearches((current) => current + 1);
  const redeem = (name: string, cost: number) => {
    if (credits < cost) {
      setRedeemedReward("Creditos insuficientes para " + name);
      return;
    }
    setCredits((current) => current - cost);
    setRedeemedReward("Canjeado: " + name);
  };
  const submitAccess = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAccessMessage("Formulario demo enviado. En producto real crearia sesion JWT y perfil inicial.");
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <button className="brand-lockup button-reset" onClick={() => navigate("inicio")} aria-label="Inicio Swinra">
          <span className="brand-mark">S</span>
          <span>{brand.name}</span>
        </button>
        <nav className="nav-links" aria-label="Navegacion principal">
          {validViews.slice(1).map((item) => (
            <button className={view === item ? "active" : ""} key={item} onClick={() => navigate(item)}>
              {item === "acceso" ? "Acceso" : item.charAt(0).toUpperCase() + item.slice(1)}
            </button>
          ))}
        </nav>
      </header>

      {view === "inicio" && (
        <>
          <section className="home-hero">
            <div className="hero-copy">
              <p className="eyebrow">Web MVP para comunidad privada</p>
              <h1>{brand.name}</h1>
              <p>{brand.tagline}. Una experiencia separada por vistas: acceso, matching, comunidad, premium y creditos.</p>
              <div className="hero-actions">
                <button className="primary-action" onClick={() => navigate("matching")}>
                  Explorar perfiles <ChevronRight size={18} />
                </button>
                <button className="secondary-action" onClick={() => navigate("acceso")}>
                  Crear cuenta demo
                </button>
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
                <span>Creditos disponibles</span>
                <strong>{credits}</strong>
                <p>Se ganan por confianza, actividad y premium.</p>
              </div>
            </div>
          </section>

          <section className="feature-strip" aria-label="Capacidades principales">
            <article>
              <ShieldCheck size={22} />
              <h2>Confianza</h2>
              <p>Verificacion opcional, badges, resenas verificadas y niveles de reputacion.</p>
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
              <Coins size={22} />
              <h2>Creditos</h2>
              <p>Puntos canjeables por regalos, boosts, super-puntuaciones y skins.</p>
            </article>
          </section>
        </>
      )}

      {view === "dashboard" && (
        <>
          <section className="hero-band">
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
                <button className="icon-action" aria-label="Solicitar album privado" onClick={() => navigate("premium")}>
                  <Lock size={18} /> Solicitar
                </button>
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
                <button className="icon-action" onClick={() => setShowReport((current) => !current)}>
                  <BarChart3 size={18} /> Informe
                </button>
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
        </>
      )}

      {view === "matching" && (
        <section className="content-grid single-view">
          <section className="panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Matching</p>
                <h2>Busqueda avanzada</h2>
              </div>
              <button className="icon-action" onClick={saveSearch}>
                <Bookmark size={18} /> Guardar busqueda
              </button>
            </div>
            <p className="action-feedback">{savedSearches} busquedas guardadas con alerta automatica.</p>
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
                      <Eye size={14} /> {profile.photos?.filter((photo) => photo.visibility === "public").length ?? 0}{" "}
                      fotos visibles
                    </small>
                  </div>
                  <strong>{profile.average_score.toFixed(1)}</strong>
                </article>
              ))}
            </div>
          </section>

          <section className="panel side-panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Siguiente accion</p>
                <h2>Solicitud segura</h2>
              </div>
              <Send size={22} />
            </div>
            <div className="stack-list">
              <article className="list-item">
                <span>Paso 1</span>
                <h3>Solicitar conexion</h3>
                <p>El otro perfil acepta antes de abrir chat o album privado.</p>
              </article>
              <article className="list-item">
                <span>Paso 2</span>
                <h3>Checklist de consentimiento</h3>
                <p>Preferencias, limites, disponibilidad y privacidad antes de quedar.</p>
              </article>
              <article className="list-item">
                <span>Paso 3</span>
                <h3>Resena posterior</h3>
                <p>Solo las interacciones confirmadas pueden puntuar y comentar.</p>
              </article>
            </div>
          </section>
        </section>
      )}

      {view === "comunidad" && (
        <section className="content-grid single-view">
          <section className="panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Comunidad</p>
                <h2>Foros y eventos</h2>
              </div>
              <div className="inline-actions">
                <button className="icon-action" onClick={() => setCommunityComposer("post")}>
                  <Plus size={18} /> Post
                </button>
                <button className="icon-action" onClick={() => setCommunityComposer("event")}>
                  <CalendarDays size={18} /> Evento
                </button>
              </div>
            </div>
            {communityComposer && (
              <form className="inline-composer" onSubmit={(event) => event.preventDefault()}>
                <label>
                  {communityComposer === "post" ? "Titulo del post" : "Titulo del evento"}
                  <input placeholder={communityComposer === "post" ? "Nueva guia para la comunidad" : "Velada privada"} />
                </label>
                <button className="primary-action" type="submit">
                  Guardar borrador
                </button>
              </form>
            )}
            <div className="stack-list">
              {data.forumPosts.map((post) => (
                <article className="list-item" key={post.id}>
                  <span>{post.topic}</span>
                  <h3>{post.title}</h3>
                  <p>
                    {post.points} puntos - {post.replies} respuestas
                  </p>
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

          <section className="panel side-panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Ranking mensual</p>
                <h2>Actividad con calidad</h2>
              </div>
              <Trophy size={22} />
            </div>
            <div className="table compact-table">
              <div className="table-row table-head">
                <span>Perfil</span>
                <span>Puntos</span>
              </div>
              <div className="table-row">
                <span>Luna & Marco</span>
                <span>1260</span>
              </div>
              <div className="table-row">
                <span>Nexo Duo</span>
                <span>980</span>
              </div>
              <div className="table-row">
                <span>Iris</span>
                <span>710</span>
              </div>
            </div>
          </section>
        </section>
      )}

      {view === "premium" && (
        <>
          <section className="content-grid">
            <section className="panel main-panel">
              <div className="panel-title">
                <div>
                  <p className="eyebrow">Reputacion</p>
                  <h2>Evolucion mensual</h2>
                </div>
                <button className="icon-action" onClick={() => setShowReport((current) => !current)}>
                  <Sparkles size={18} /> {showReport ? "Ocultar informe" : "Ver informe"}
                </button>
              </div>
              <ReputationChart data={data.reputation} />
              <ProgressBar value={data.profile.profile_progress} label="Completitud del perfil" />
              <div className="badge-list">
                {data.profile.badges.map((badge) => (
                  <BadgePill badge={badge} key={badge.code} />
                ))}
              </div>
              {showReport && (
                <div className="insight-box">
                  <strong>Informe premium</strong>
                  <p>
                    Tu reputacion sube por resenas verificadas, perfil completo y actividad de calidad. Siguiente mejora:
                    pedir 2 resenas tras eventos confirmados.
                  </p>
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-title">
                <div>
                  <p className="eyebrow">Premium en tiempo real</p>
                  <h2>Pareja mas vista</h2>
                </div>
                <button className="icon-action" onClick={() => setHotlistSaved((current) => !current)}>
                  <Star size={18} /> {hotlistSaved ? "En hotlist" : "Guardar"}
                </button>
              </div>
              <MostViewedTable rows={data.mostViewed} isPremium={data.profile.is_premium} />
            </section>
          </section>

          <section className="pricing-grid">
            <article className="panel price-card">
              <span>Gratis</span>
              <h2>0 EUR</h2>
              <p>Perfil, busqueda basica, foros y reputacion visible.</p>
            </article>
            <article className="panel price-card highlighted">
              <span>Premium</span>
              <h2>14,90 EUR/mes</h2>
              <p>Hotlists, album privado bajo permiso, estadisticas, perfil destacado y creditos mensuales.</p>
            </article>
            <article className="panel price-card">
              <span>Elite</span>
              <h2>29,90 EUR/mes</h2>
              <p>Eventos privados, informes avanzados, prioridad de soporte y boosts incluidos.</p>
            </article>
          </section>
        </>
      )}

      {view === "creditos" && (
        <section className="content-grid single-view">
          <section className="panel wallet-panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Creditos Swinra</p>
                <h2>Balance y canje</h2>
              </div>
              <div className="wallet-balance">
                <Coins size={22} /> {credits}
              </div>
            </div>
            <div className="reward-grid">
              {rewards.map((reward) => {
                const Icon = reward.icon;
                return (
                  <article className="reward-card" key={reward.name}>
                    <Icon size={24} />
                    <h3>{reward.name}</h3>
                    <p>{reward.cost} creditos</p>
                    <button className="primary-action" onClick={() => redeem(reward.name, reward.cost)}>
                      Canjear
                    </button>
                  </article>
                );
              })}
            </div>
            {redeemedReward && <p className="action-feedback">{redeemedReward}</p>}
          </section>

          <section className="panel side-panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Como se ganan</p>
                <h2>Puntos convertibles</h2>
              </div>
              <Coins size={22} />
            </div>
            <div className="stack-list">
              {monthlyPoints.map((item) => {
                const Icon = item.icon;
                return (
                  <article className="list-item event-item" key={item.label}>
                    <span>
                      <Icon size={16} /> +{item.points}
                    </span>
                    <h3>{item.label}</h3>
                    <p>Actividad con valor para la comunidad y para la confianza del marketplace.</p>
                  </article>
                );
              })}
            </div>
          </section>
        </section>
      )}

      {view === "acceso" && (
        <section className="content-grid single-view">
          <section className="panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Acceso</p>
                <h2>Login demo</h2>
              </div>
              <LogIn size={22} />
            </div>
            <form className="auth-form" onSubmit={submitAccess}>
              <label>
                Email
                <input defaultValue="luna@example.com" type="email" />
              </label>
              <label>
                Password
                <input defaultValue="SwinraDemo1" type="password" />
              </label>
              <button className="primary-action" type="submit">
                Entrar
              </button>
            </form>
            <p className="action-feedback">{accessMessage}</p>
          </section>

          <section className="panel side-panel">
            <div className="panel-title">
              <div>
                <p className="eyebrow">Registro</p>
                <h2>Crear perfil</h2>
              </div>
              <UserPlus size={22} />
            </div>
            <div className="stack-list">
              <article className="list-item">
                <span>Tipo de usuario</span>
                <h3>Pareja o soltero</h3>
                <p>El onboarding adapta fotos, intereses, limites y expectativas.</p>
              </article>
              <article className="list-item">
                <span>Verificacion opcional</span>
                <h3>Documento o redes</h3>
                <p>La verificacion sube confianza, pero no expone datos sensibles al resto.</p>
              </article>
              <article className="list-item">
                <span>Privacidad</span>
                <h3>Album bajo permiso</h3>
                <p>El usuario decide quien puede ver fotos privadas y durante cuanto tiempo.</p>
              </article>
            </div>
          </section>
        </section>
      )}
    </main>
  );
}
