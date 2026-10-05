const path = require('path');

// Hugo root: themes/enchanted-lowkey/config -> up 3 levels
const rootDir = path.join(__dirname, '..', '..', '..');

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    `${rootDir}/layouts/**/*.html`,
    `${rootDir}/content/**/*.{html,md}`,
    `${rootDir}/themes/**/layouts/**/*.html`,
  ],
  theme: {
    extend: {
      fontFamily: {
        'sans': ['"Inter"', '-apple-system', 'BlinkMacSystemFont', 'avenir next', 'avenir', 'segoe ui', 'helvetica neue', 'helvetica', 'Cantarell', 'Ubuntu', 'roboto', 'noto', 'arial', 'sans-serif'],
      },
    },
  },
  plugins: [],
}