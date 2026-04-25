import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { MostViewedTable } from "./MostViewedTable";

const rows = [{ couple_name: "Nexo Duo", average_score: 4.7, visits: 318, current_badge: "Veterano Swinger" }];

describe("MostViewedTable", () => {
  it("locks the widget for non premium users", () => {
    render(<MostViewedTable rows={rows} isPremium={false} />);
    expect(screen.getByTestId("premium-locked")).toBeInTheDocument();
  });

  it("shows the premium ranking for premium users", () => {
    render(<MostViewedTable rows={rows} isPremium />);
    expect(screen.getByTestId("most-viewed-widget")).toBeInTheDocument();
    expect(screen.getByText("Nexo Duo")).toBeInTheDocument();
  });
});
