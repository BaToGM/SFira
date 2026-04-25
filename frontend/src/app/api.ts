import { apiBaseUrl } from "./config";
import type {
  AnalyticsSummary,
  EventItem,
  ForumPost,
  MostViewedCouple,
  Profile,
  ReputationPoint,
} from "../features/types";

export type DashboardData = {
  profile: Profile;
  matches: Profile[];
  reputation: ReputationPoint[];
  mostViewed: MostViewedCouple[];
  forumPosts: ForumPost[];
  events: EventItem[];
  analytics: AnalyticsSummary;
};

const demoProfile: Profile = {
  id: "demo-profile",
  display_name: "Luna & Marco",
  user_type: "couple",
  headline: "Conexiones cuidadas, buen humor y planes con quimica.",
  location: "Madrid",
  orientation: "bi-curious",
  interests: ["eventos", "cenas", "viajes"],
  fetishes: ["roleplay", "lingerie"],
  profile_progress: 86,
  average_score: 4.9,
  reputation_level: "elite",
  visits: 244,
  is_verified: true,
  is_premium: true,
  photos: [
    {
      id: "luna-marco-cover",
      url: "/demo-photos/luna-marco-cover.svg",
      alt: "Foto principal de Luna & Marco",
      is_primary: true,
      visibility: "public",
    },
    {
      id: "luna-marco-social",
      url: "/demo-photos/luna-marco-social.svg",
      alt: "Album social de Luna & Marco",
      is_primary: false,
      visibility: "public",
    },
    {
      id: "luna-marco-private",
      url: "/demo-photos/luna-marco-private.svg",
      alt: "Album privado de Luna & Marco",
      is_primary: false,
      visibility: "private",
    },
  ],
  reviews: [
    {
      id: "review-1",
      author: "Encuentro verificado",
      score: 5,
      comment: "Trato respetuoso, comunicacion clara y expectativas bien cuidadas.",
      interaction_type: "in_person",
      created_at: new Date(Date.now() - 86400000 * 9).toISOString(),
      is_verified_interaction: true,
    },
    {
      id: "review-2",
      author: "Conexion virtual",
      score: 4.8,
      comment: "Conversacion fluida y muy buen seguimiento antes de quedar.",
      interaction_type: "virtual",
      created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
      is_verified_interaction: true,
    },
  ],
  badges: [
    { code: "explorer", label: "Explorador", tone: "soft" },
    { code: "fira_star", label: "Fira Star", tone: "gold" },
    { code: "premium_star", label: "Premium Star", tone: "gold" },
  ],
};

const demoData: DashboardData = {
  profile: demoProfile,
  matches: [
    demoProfile,
    {
      ...demoProfile,
      id: "nexo",
      display_name: "Nexo Duo",
      headline: "Planes selectos, conversacion honesta y mucha discrecion.",
      average_score: 4.7,
      visits: 318,
      interests: ["hotlists", "eventos", "weekends"],
      fetishes: ["lingerie", "wellness"],
      photos: [
        {
          id: "nexo-cover",
          url: "/demo-photos/nexo-cover.svg",
          alt: "Foto principal de Nexo Duo",
          is_primary: true,
          visibility: "public",
        },
        {
          id: "nexo-social",
          url: "/demo-photos/nexo-social.svg",
          alt: "Album social de Nexo Duo",
          is_primary: false,
          visibility: "public",
        },
      ],
      badges: [{ code: "veteran_swinger", label: "Veterano Swinger", tone: "hot" }],
    },
    {
      ...demoProfile,
      id: "iris",
      display_name: "Iris",
      user_type: "single",
      headline: "Curiosa, directa y con ganas de conocer gente con buen trato.",
      location: "Barcelona",
      average_score: 4.3,
      visits: 138,
      interests: ["foros", "cenas", "virtual"],
      fetishes: ["wellness"],
      photos: [
        {
          id: "iris-cover",
          url: "/demo-photos/iris-cover.svg",
          alt: "Foto principal de Iris",
          is_primary: true,
          visibility: "public",
        },
        {
          id: "iris-social",
          url: "/demo-photos/iris-social.svg",
          alt: "Album social de Iris",
          is_primary: false,
          visibility: "public",
        },
      ],
      badges: [{ code: "explorer", label: "Explorador", tone: "soft" }],
    },
    {
      ...demoProfile,
      id: "salma-rio",
      display_name: "Salma & Rio",
      headline: "Buscamos eventos tranquilos y afinidad antes de cualquier plan.",
      location: "Valencia",
      average_score: 4.6,
      visits: 201,
      interests: ["eventos", "viajes", "cultura"],
      fetishes: ["roleplay"],
      photos: [
        {
          id: "salma-rio-cover",
          url: "/demo-photos/salma-rio-cover.svg",
          alt: "Foto principal de Salma & Rio",
          is_primary: true,
          visibility: "public",
        },
        {
          id: "salma-rio-social",
          url: "/demo-photos/salma-rio-social.svg",
          alt: "Album social de Salma & Rio",
          is_primary: false,
          visibility: "public",
        },
      ],
      badges: [{ code: "fira_star", label: "Fira Star", tone: "gold" }],
    },
  ],
  reputation: [
    { label: "Ene", average_score: 4.1 },
    { label: "Feb", average_score: 4.3 },
    { label: "Mar", average_score: 4.5 },
    { label: "Abr", average_score: 4.9 },
  ],
  mostViewed: [
    { couple_name: "Nexo Duo", average_score: 4.7, visits: 318, current_badge: "Veterano Swinger" },
    { couple_name: "Luna & Marco", average_score: 4.9, visits: 244, current_badge: "Premium Star" },
  ],
  forumPosts: [
    {
      id: "post-1",
      author: "Luna & Marco",
      title: "Como preparar una primera quedada comoda",
      topic: "Primeros pasos",
      points: 88,
      replies: 12,
    },
    {
      id: "post-2",
      author: "Iris",
      title: "Ideas para eventos virtuales cuidados",
      topic: "Eventos",
      points: 52,
      replies: 6,
    },
    {
      id: "post-3",
      author: "Nexo Duo",
      title: "Checklist de consentimiento para nuevos encuentros",
      topic: "Confianza",
      points: 73,
      replies: 9,
    },
  ],
  events: [
    {
      id: "event-1",
      title: "Velada Swinra",
      mode: "virtual",
      starts_at: new Date().toISOString(),
      rsvp_count: 28,
    },
    {
      id: "event-2",
      title: "Copa privada en Madrid",
      mode: "in_person",
      starts_at: new Date(Date.now() + 86400000 * 6).toISOString(),
      location: "Madrid",
      rsvp_count: 18,
    },
  ],
  analytics: { clicks: 482, views: 2360, gifts_sent: 37, reputation_percentile: 91 },
};

async function request<T>(path: string, token?: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function loginDemo(): Promise<string> {
  const response = await fetch(`${apiBaseUrl}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "luna@example.com", password: "SwinraDemo1" }),
  });
  if (!response.ok) {
    throw new Error("Demo login failed");
  }
  const payload = (await response.json()) as { access_token: string };
  return payload.access_token;
}

export async function fetchDashboardData(): Promise<DashboardData> {
  try {
    const token = await loginDemo();
    const profile = await request<Profile>("/profiles/me", token);
    const [matches, reputation, mostViewed, forumPosts, analytics] = await Promise.all([
      request<Profile[]>("/matching/search?min_score=3.5"),
      request<ReputationPoint[]>(`/reputation/${profile.id}/history`),
      request<MostViewedCouple[]>("/premium/most-viewed-couples", token),
      request<ForumPost[]>("/community/forum-posts"),
      request<AnalyticsSummary>("/premium/analytics", token),
    ]);
    return {
      profile,
      matches,
      reputation,
      mostViewed,
      forumPosts,
      events: await request<EventItem[]>("/events"),
      analytics,
    };
  } catch {
    return demoData;
  }
}
