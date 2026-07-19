import type { Session } from "../types.js";

export function SessionIdentity({ session }: { session: Session }) {
  return (
    <div className="flex items-center justify-between gap-2 text-xs" aria-label="Signed-in user">
      <span className="flex min-w-0 items-center gap-2">
        {session.picture ? (
          <img
            src={session.picture}
            alt=""
            className="size-6 rounded-full"
            referrerPolicy="no-referrer"
          />
        ) : (
          <span
            className="grid size-6 place-items-center rounded-full"
            aria-hidden
            style={{ background: "var(--color-accent-soft)" }}
          >
            {(session.name || session.email || "S").slice(0, 1).toUpperCase()}
          </span>
        )}
        <span className="min-w-0">
          <span className="block truncate font-medium">{session.name || "Shauth user"}</span>
          {session.email ? (
            <span className="block truncate" style={{ color: "var(--color-fg-subtle)" }}>
              {session.email}
            </span>
          ) : null}
        </span>
      </span>
      <form action="/auth/logout" method="post">
        <button
          className="rounded px-2 py-1 text-xs"
          style={{ border: "1px solid var(--color-border)", color: "var(--color-fg)" }}
          type="submit"
        >
          Log out
        </button>
      </form>
    </div>
  );
}
