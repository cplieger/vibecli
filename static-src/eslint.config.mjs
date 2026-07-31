// App-local ESLint config for web-terminal-kiro's front end.
//
// The shared, org-synced ruleset lives in eslint.config.base.mjs (synced from
// cplieger/ci). Do NOT edit the base here -- the next sync would clobber it. This
// file imports it and layers on the one repo-specific delta: the scratch trees
// below.
//
// The base sits in THIS directory rather than the repo root, and that is what
// makes importing it possible at all. Node resolves a bare specifier from the
// importing module's own directory upward, so while the base lived at the repo
// root it could not resolve its own `@eslint/js` / `typescript-eslint` imports --
// this app's dependencies are installed here, beside its package.json:
//
//   Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@eslint/js'
//     imported from <repo>/eslint.config.base.mjs
//
// So this file used to be a full COPY of the base, and every canonical
// improvement silently bypassed the linter that actually runs. cplieger/ci's
// classify-repos.py now syncs the base beside each TS package.json, which also
// fixes the base's `tsconfigRootDir: import.meta.dirname`: from here it resolves
// to the directory that actually holds tsconfig.json.
import baseConfig from "./eslint.config.base.mjs";

export default [
  ...baseConfig,
  {
    // Stryker's sandbox + report output and the Kiro skill scratch trees. All are
    // gitignored, but ESLint flat config does not read .gitignore (and no longer
    // ignores dot-directories by default), so a leftover sandbox (an interrupted
    // mutation run never cleans it up) or a review run makes `npm run lint:eslint`
    // fail on hundreds of copied, @ts-nocheck-stamped files. .prettierignore and
    // vitest.config.ts exclude the same trees for the same reason.
    //
    // App-local by design, not a candidate for the canonical config: these are
    // this repo's scratch trees. The equivalent parity problem in the CENTRAL
    // lint steps (stylelint, html-validate) is solved where it belongs, in
    // cplieger/ci's _ci_local.py gitignore rewrites, not by pushing app scratch
    // names into a fleet-wide config.
    ignores: ["**/.stryker-tmp/**", "**/reports/**", "**/.code-review/**"],
  },
];
