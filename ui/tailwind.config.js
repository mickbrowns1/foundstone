/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#0F0F1A',
          deep: '#1A1A2E',
          card: '#16213E',
          surface: '#1E293B',
        },
        accent: {
          DEFAULT: '#7C3AED',
          light: '#8B5CF6',
          hover: '#6D28D9',
        },
        border: {
          DEFAULT: '#2D3748',
          light: '#4A5568',
        },
      },
    },
  },
  plugins: [],
}
