import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SessionIdentity } from "../components/SessionIdentity.js";

describe("SessionIdentity", () => {
  it("renders the signed-in user's avatar, name, email, and logout control", () => {
    const { container } = render(
      <SessionIdentity
        session={{
          authenticated: true,
          name: "octocat",
          email: "octocat@example.com",
          picture: "https://avatars.example.com/octocat.png",
          role: "developer",
        }}
      />,
    );

    expect(screen.getByLabelText("Signed-in user")).toBeDefined();
    expect(screen.getByText("octocat")).toBeDefined();
    expect(screen.getByText("octocat@example.com")).toBeDefined();
    expect(container.querySelector('img[src="https://avatars.example.com/octocat.png"]')).not.toBeNull();
    expect(screen.getByRole("button", { name: "Log out" })).toBeDefined();
    expect(container.querySelector('form[action="/auth/logout"][method="post"]')).not.toBeNull();
  });

  // Post-deployment qualification finds the signed-in user and the real
  // sign-out control through these markers, and the username must be exactly
  // what the provider asserted.
  it("marks the signed-in user and the real sign-out control for qualification", () => {
    const { container } = render(
      <SessionIdentity session={{ authenticated: true, name: "octocat", role: "developer" }} />,
    );

    expect(container.querySelector("[data-shauth-user]")?.getAttribute("data-shauth-user")).toBe(
      "octocat",
    );
    expect(container.querySelector("[data-shauth-sign-out]")?.tagName).toBe("BUTTON");
  });

  it("uses an initial when the identity has no avatar", () => {
    render(<SessionIdentity session={{ authenticated: true, name: "Developer", role: "developer" }} />);
    expect(screen.getByText("D")).toBeDefined();
  });
});
