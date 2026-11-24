/** @type {import('tailwindcss').Config} */
module.exports = {
  // Only our own sources are scanned; the vendored *.min.js libraries are not.
  content: [
    "../app/templates/**/*.html",
    "../app/static/js/app.js",
    "../app/static/js/login.js",
    "../app/static/js/route-access.js",
    "../app/static/js/tones.js",
    "../app/static/js/updates.js",
    "../app/static/js/theme.js",
  ],
  // theme.js toggles the `dark` class on <html>.
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        primary: {
          50: "#f0f9ff",
          100: "#e0f2fe",
          200: "#bae6fd",
          300: "#7dd3fc",
          400: "#38bdf8",
          500: "#0ea5e9",
          600: "#0284c7",
          700: "#0369a1",
          800: "#075985",
          900: "#0c4a6e",
          950: "#082f49",
        },
        dark: {
          bg: "#0f172a",
          surface: "#1e293b",
          border: "#334155",
        },
        // Semantic colours that switch with the theme. The values are CSS
        // variables defined in src/tailwind.css, so one class works in both.
        ui: {
          surface: "var(--ui-surface)",
          "surface-muted": "var(--ui-surface-muted)",
          line: "var(--ui-line)",
          fg: "var(--ui-fg)",
          muted: "var(--ui-muted)",
          focus: "var(--ui-focus)",
          accent: "var(--ui-accent)",
          "accent-hover": "var(--ui-accent-hover)",
          danger: "var(--ui-danger)",
        },
        // The same idea for the dashboard panels.
        db: {
          panel: "var(--db-panel)",
          "panel-line": "var(--db-panel-line)",
          line: "var(--db-line)",
          fg: "var(--db-fg)",
          muted: "var(--db-muted)",
          track: "var(--db-track)",
          surface: "var(--db-surface)",
          accent: "var(--db-accent)",
          ok: "#10b981",
          warn: "#f59e0b",
          crit: "#ef4444",
          down: "#0ea5e9",
          up: "#6366f1",
        },
      },
      fontFamily: {
        sans: ["Plus Jakarta Sans", "sans-serif"],
        heading: ["Outfit", "sans-serif"],
      },
      animation: {
        // Per-star timing is set inline; these are the defaults.
        "shooting-star": "shootingStar 12s linear infinite",
        twinkle: "twinkle 4s ease-in-out infinite",
      },
      keyframes: {
        // A star streaks along its own axis, then rests until the next cycle.
        shootingStar: {
          "0%": { transform: "translateX(0)", opacity: "0" },
          "2%": { opacity: "1" },
          "22%": { opacity: "0.9" },
          "30%, 100%": { transform: "translateX(var(--travel, 75vmax))", opacity: "0" },
        },
        twinkle: {
          "0%, 100%": { opacity: "0.2" },
          "50%": { opacity: "1" },
        },
      },
    },
  },
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/container-queries"),
  ],
};
