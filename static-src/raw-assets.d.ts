// Types for Vite's `?raw` import suffix, which app.test.ts uses to read the
// SERVED static assets (index.html, manifest.json, the favicon variants) and two
// non-exported files from the UI package as text.
//
// Declared here rather than by adding "vite/client" to tsconfig.test.json's
// `types`: vite is a transitive dependency of vitest, not a direct one, so
// naming it there would make this package depend on a package it does not
// declare. Only the `?raw` suffix is used, so only `?raw` is declared -- a
// mistyped `?url` or `?inline` import must fail to compile rather than silently
// resolve to a string.
declare module "*?raw" {
  const content: string;
  export default content;
}
