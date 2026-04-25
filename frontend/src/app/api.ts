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
      average_score: 4.7,
      visits: 318,
      badges: [{ code: "veteran_swinger", label: "Veterano Swinger", tone: "hot" }],
    },
    {
      ...demoProfile,
      id: "iris",
      display_name: "Iris",
      user_type: "single",
      average_score: 4.3,
      visits: 138,
      badges: [{ code: "explorer", label: "Explorador", tone: "soft" }],
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
  ],
  events: [
    {
      id: "event-1",
      title: "Velada Swinra",
      mode: "virtual",
      starts_at: new Date().toISOString(),
      rsvp_count: 28,
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
