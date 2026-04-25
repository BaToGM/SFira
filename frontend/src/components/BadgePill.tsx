import type { Badge } from "../features/types";

type Props = {
  badge: Badge;
};

export function BadgePill({ badge }: Props) {
  return <span className={`badge badge-${badge.tone}`}>{badge.label}</span>;
}
