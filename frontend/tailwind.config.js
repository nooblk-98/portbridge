/** @type {import('tailwindcss').Config} */
module.exports = {
  // Only our own sources are scanned; the vendored *.min.js libraries are not.
  content: [
    "../app/templates/**/*.html",
    "../app/static/js/app.js",
    "../app/static/js/login.js",
    "../app/static/js/route-access.js",
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
      },
      fontFamily: {
        sans: ["Plus Jakarta Sans", "sans-serif"],
        heading: ["Outfit", "sans-serif"],
      },
      animation: {
        "fade-in": "fadeIn 0.3s ease-out",
        "slide-up": "slideUp 0.4s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { transform: "translateY(20px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
      },
    },
  },
  plugins: [require("@tailwindcss/forms"), require("@tailwindcss/typography")],
};
