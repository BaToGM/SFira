export type UserType = "couple" | "single";

export type Badge = {
  code: string;
  label: string;
  tone: "soft" | "hot" | "gold" | "elite";
};

export type Profile = {
  id: string;
  display_name: string;
  user_type: UserType;
  headline: string;
  location: string;
  orientation: string;
  interests: string[];
  fetishes: string[];
  profile_progress: number;
  average_score: number;
  reputation_level: string;
  badges: Badge[];
  visits: number;
  is_verified: boolean;
  is_premium: boolean;
};

export type ReputationPoint = {
  label: string;
  average_score: number;
};

export type MostViewedCouple = {
  couple_name: string;
  average_score: number;
  visits: number;
  current_badge: string;
};

export type ForumPost = {
  id: string;
  author: string;
  title: string;
  topic: string;
  points: number;
  replies: number;
};

export type EventItem = {
  id: string;
  title: string;
  mode: "virtual" | "in_person";
  starts_at: string;
  location?: string;
  rsvp_count: number;
};

export type AnalyticsSummary = {
  clicks: number;
  views: number;
  gifts_sent: number;
  reputation_percentile: number;
};
