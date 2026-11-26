/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bento: {
          canvas: '#101416',
          sidebar: '#151A1E',
          surface: '#1C2226',
          surface2: '#272F35',
          border: '#343D43',
          text: '#F2F4F5',
          'text-secondary': '#A1ABB3',
          'text-muted': '#8E99A2',
          accent: '#5795F2',
          'accent-light': '#79ABFF',
          warning: '#F2A544',
          critical: '#E56B6F',
          'critical-text': '#F08A8D',
          success: '#36C995',
          'vector-aitm': '#9D8CF5',
          'vector-aitm-text': '#B0A1F8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Manrope', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: {
        control: '10px',
        bento: '16px',
        overlay: '20px',
      },
      transitionTimingFunction: {
        'ease-out-ui': 'cubic-bezier(0.23, 1, 0.32, 1)',
        'ease-in-out-ui': 'cubic-bezier(0.77, 0, 0.175, 1)',
        'ease-drawer': 'cubic-bezier(0.32, 0.72, 0, 1)',
      },
    },
  },
  plugins: [],
};
