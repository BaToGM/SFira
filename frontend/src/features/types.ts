export type UserType = "couple" | "single";

export type Badge = {
  code: string;
  label: string;
  tone: "soft" | "hot" | "gold" | "elite";
};

export type ProfilePhoto = {
  id: string;
  url: string;
  alt: string;
  is_primary: boolean;
  visibility: "public" | "private";
};

export type ProfileReview = {
  id: string;
  author: string;
  score: number;
  comment: string;
  interaction_type: "chat" | "virtual" | "in_person";
  created_at: string;
  is_verified_interaction: boolean;
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
  photos: ProfilePhoto[];
  reviews: ProfileReview[];
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
