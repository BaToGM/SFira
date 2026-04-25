import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProgressBar } from "./ProgressBar";

describe("ProgressBar", () => {
  it("shows profile completion percentage", () => {
    render(<ProgressBar label="Completitud del perfil" value={72} />);
    expect(screen.getByText("72%")).toBeInTheDocument();
    expect(screen.getByLabelText("Completitud del perfil")).toBeInTheDocument();
  });
});
