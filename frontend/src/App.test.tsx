import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Provider } from "react-redux";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { store } from "./app/store";

describe("Swinra dashboard", () => {
  it("renders dashboard, progress and matching filters with demo fallback", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    window.location.hash = "#dashboard";

    render(
      <Provider store={store}>
        <App />
      </Provider>,
    );

    await waitFor(() => expect(screen.getByRole("heading", { name: "Luna & Marco", level: 2 })).toBeInTheDocument());
    expect(screen.getByText("Perfil completo")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Fotos y album privado", level: 2 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Resenas verificadas", level: 2 })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Matching" }));
    expect(await screen.findByTestId("matching-filters")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Premium" }));
    expect(await screen.findByTestId("most-viewed-widget")).toBeInTheDocument();
  });
});
