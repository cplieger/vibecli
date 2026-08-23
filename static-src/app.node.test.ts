// The half of this app's suite that cannot run in the browser project.
//
// Placement is in the `.node` suffix and the reason is in what each test reads.
// Every other test in this package drives real DOM and runs in headless
// Chromium (see app.test.ts); these four read the SHIPPED tree from disk in ways
// no Vite import can express:
//
//   - the vendored-graph importmap test walks two DEPENDENCY src trees inside
//     node_modules recursively and TS-parses every file it finds. `?raw` names
//     one file; `import.meta.glob` will not reliably reach into a linked or
//     published dependency's sources, and this test explicitly guards its own
//     walk (an empty walk would pass forever), so a silently-empty glob is the
//     exact failure mode it exists to prevent.
//   - the icon-inventory test derives its file list AT RUNTIME from the served
//     markup and the manifest, then reads PNG header BYTES. A static import
//     cannot express a runtime-derived list, and the pinned Vite has no
//     `?arraybuffer`.
//   - the favicon-variant test asserts a SERVED DIRECTORY LISTING. A build-time
//     glob over the source tree answers a different question.
//   - the app.ts importmap test rides with the vendored-graph one because they
//     share `browserResolvedSpecifiers`, whose whole point is that no second,
//     weaker copy of it exists. Splitting them would put that extractor in two
//     files and pull the TypeScript compiler into the browser bundle for one
//     assertion.
//
// Both describe names match app.test.ts's on purpose: these tests were split out
// of that file and belong to the same two suites.
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

// The single fixture-location policy for every file this suite reads. INIT_CWD is
// set by the npm/npx launcher to the real static-src directory, so fixtures are
// found even when the runner changes process.cwd() — Stryker's dry run executes
// inside its .stryker-tmp sandbox, where a cwd-relative read ENOENTs.
function fixtureRoot(): string {
  return process.env["INIT_CWD"] ?? process.cwd();
}

// Read one of the SERVED static assets next to static-src.
function readStaticAsset(name: string): string {
  return readFileSync(resolve(fixtureRoot(), `../static/${name}`), "utf8");
}

// Every module specifier the BROWSER resolves at load time, read from the
// TypeScript AST rather than matched by regex. app.ts ships as a plain tsc emit,
// so every static import survives verbatim -- including forms a clause-shaped
// pattern silently drops, such as the legal quoted import name
// `import { "x" as x } from "@scope/pkg"`, whose specifier a regex that stops at
// the first quote never sees. An extractor that returns nothing for a real import
// leaves its caller asserting over an empty list and passing forever, so the
// parser that emits the code is the only extractor that cannot fall behind it.
// `import type` is excluded because tsc erases it, so it never reaches module
// resolution; side-effect imports, dynamic `import()` string literals and
// `export ... from "<specifier>"` re-exports are included because the browser
// resolves all three.
function browserResolvedSpecifiers(source: string): string[] {
  const parsed = ts.createSourceFile("app.ts", source, ts.ScriptTarget.ESNext, true);
  const specifiers: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      if (node.importClause?.isTypeOnly !== true && ts.isStringLiteralLike(node.moduleSpecifier)) {
        specifiers.push(node.moduleSpecifier.text);
      }
    } else if (ts.isExportDeclaration(node)) {
      // `export ... from "<specifier>"` is resolved by the browser exactly like an
      // import. app.ts has none, but the vendored-graph test below points this
      // extractor at barrel-heavy library src trees where the form is idiomatic,
      // and a re-exported bare specifier missing from the importmap breaks the
      // whole module graph. `export type ... from` is erased by tsc, so it is
      // excluded the same way `import type` is.
      if (
        node.isTypeOnly !== true &&
        node.moduleSpecifier !== undefined &&
        ts.isStringLiteralLike(node.moduleSpecifier)
      ) {
        specifiers.push(node.moduleSpecifier.text);
      }
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const first = node.arguments[0];
      if (first !== undefined && ts.isStringLiteralLike(first)) {
        specifiers.push(first.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(parsed, visit);
  return specifiers;
}

// The served markup's <link> elements as {rel tokens, href, sizes}. app.test.ts
// reads the same file through a real DOMParser; this file runs in Node, where
// there is none, so the tags are scanned instead — and `rel` is compared BY
// TOKEN, the way a `rel~="icon"` selector matches, so a future
// `rel="icon mask-icon"` still qualifies while a `rel="icon-foo"` still does not.
// Attribute order is not assumed and all three HTML quoting forms are accepted,
// because the markup edit this feeds is precisely what these tests exist to
// catch.
function servedLinkElements(html: string): { rel: string[]; href: string; sizes: string | null }[] {
  const attribute = (tag: string, name: string): string | null => {
    const match = new RegExp(
      `\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'\`=<>]+))`,
      "i",
    ).exec(tag);
    if (match === null) {
      return null;
    }
    return match[1] ?? match[2] ?? match[3] ?? "";
  };
  return [...html.matchAll(/<link\b([^>]*)>/gi)].map((match) => {
    const tag = match[1] ?? "";
    return {
      rel: (attribute(tag, "rel") ?? "").split(/\s+/).filter((token) => token !== ""),
      href: attribute(tag, "href") ?? "",
      sizes: attribute(tag, "sizes"),
    };
  });
}

describe("web-terminal-kiro bootstrap (app.ts)", () => {
  it("serves every icon index.html and manifest.json reference, at the declared size", () => {
    // Nothing else checks these. The icons are referenced by NAME from two static
    // files no compiler reads, the watchdog deliberately ignores a failed icon link
    // (icon 404s must never raise the fatal dialog), and routes_test.go serves
    // fstest fixtures rather than the real tree -- so a renamed or regenerated
    // asset ships as a 404 favicon and an uninstallable PWA (a manifest icon that
    // does not fetch invalidates the install prompt) with nothing failing.
    // Only COMMITTED assets are checked: /style.css and /app.js are gitignored
    // build outputs, absent from a fresh checkout.
    const linked = servedLinkElements(readStaticAsset("index.html"))
      .filter((link) => link.rel.includes("icon") || link.rel.includes("apple-touch-icon"))
      .map((link) => ({ src: link.href, sizes: link.sizes }));
    const manifest: unknown = JSON.parse(readStaticAsset("manifest.json"));
    const icons = (manifest as { icons: { src: string; sizes: string }[] }).icons;
    // Neither list may be empty, or every assertion below is vacuous. Counts are
    // deliberately not pinned: adding or dropping an icon is a legitimate edit.
    expect(linked.length).toBeGreaterThan(0);
    expect(icons.length).toBeGreaterThan(0);

    for (const { src, sizes } of [...linked, ...icons]) {
      const path = resolve(fixtureRoot(), `../static/${src.replace(/^\//, "")}`);
      expect(
        () => readFileSync(path),
        `${src} is referenced but not present in static/`,
      ).not.toThrow();
      if (sizes === null || !src.endsWith(".png")) {
        continue;
      }
      // The PNG IHDR width/height, so a regenerated asset cannot keep a stale
      // declared size: an icon whose real pixels disagree with its `sizes` is
      // rejected by some install prompts and rasterised wrong by others.
      const header = readFileSync(path);
      expect(`${header.readUInt32BE(16)}x${header.readUInt32BE(20)}`, `${src} pixels`).toBe(sizes);
    }
  });

  it("declares an importmap entry for every bare specifier app.ts imports", () => {
    // app.ts ships as a plain tsc emit -- no bundler rewrites its bare
    // specifiers -- so the browser resolves every one of them through
    // index.html's inline importmap alone. app.test.ts mocks both packages and
    // the image build only checks three hardcoded emit paths, so importing a
    // subpath the importmap does not name compiles, ships, and then fails at
    // module load for every visitor (the watchdog's own fatal dialog) with
    // every DOM test still green.
    const source = readFileSync(resolve(fixtureRoot(), "app.ts"), "utf8");
    const specifiers = browserResolvedSpecifiers(source).filter(
      (specifier) => !specifier.startsWith(".") && !specifier.startsWith("/"),
    );
    // Guard the extractor itself: an extractor that silently matched nothing
    // would leave the loop below asserting over an empty list and passing forever.
    expect(specifiers).toContain("@cplieger/web-terminal-ui");
    expect(specifiers).toContain("@cplieger/web-terminal-ui/presets");
    // ...and pin its reach against a fixture of every form tsc emits unchanged,
    // so no supported import syntax can fall out of the extractor unnoticed. The
    // quoted import name is the one a clause-shaped regex dropped; the type-only
    // import is absent because tsc erases it, and the relative specifier is kept
    // here (the bare-specifier filter above is the caller's, not the extractor's).
    expect(
      browserResolvedSpecifiers(
        [
          `import { "x" as x } from "@scope/quoted-name";`,
          `import "@scope/side-effect";`,
          `import def, { named } from "@scope/clause";`,
          `import type { T } from "@scope/erased";`,
          `void import("@scope/dynamic");`,
          `import { local } from "./local.js";`,
        ].join("\n"),
      ),
    ).toEqual([
      "@scope/quoted-name",
      "@scope/side-effect",
      "@scope/clause",
      "@scope/dynamic",
      "./local.js",
    ]);

    const html = readStaticAsset("index.html");
    const map = /<script\b[^>]*type=["']importmap["'][^>]*>([\s\S]*?)<\/script\s*>/i.exec(html);
    const parsed: unknown = JSON.parse(map?.[1] ?? "null");
    const keys = Object.keys((parsed as { imports?: Record<string, string> })?.imports ?? {});
    for (const specifier of specifiers) {
      // The browser's own resolution rule: an exact key, or a trailing-slash
      // prefix key the specifier starts with -- so switching the map to prefix
      // form stays green.
      expect(
        keys.some((key) => key === specifier || (key.endsWith("/") && specifier.startsWith(key))),
        `no importmap entry in static/index.html resolves ${specifier}`,
      ).toBe(true);
    }
  });

  it("declares an importmap entry for every bare specifier the vendored graph imports", () => {
    // The test above covers app.ts's OWN two specifiers. The browser also resolves
    // the specifiers the VENDORED packages import: the Dockerfile compiles
    // web-terminal-ui's and web-terminal-engine's TypeScript into static/vendor/
    // with bare specifiers preserved (only relative "./*.js" paths resolve inside
    // the vendored dirs). @cplieger/web-terminal-engine is imported by the UI's
    // kernel/viewport/tabs modules and NEVER by app.ts, so deleting that importmap
    // entry puts every visitor on the watchdog's fatal dialog while the
    // app.ts-only check above stays green.
    const specifiers = new Set<string>();
    for (const pkg of ["@cplieger/web-terminal-ui", "@cplieger/web-terminal-engine"]) {
      const src = resolve(fixtureRoot(), `node_modules/${pkg}/src`);
      for (const entry of readdirSync(src, { recursive: true, encoding: "utf8" })) {
        if (!entry.endsWith(".ts")) {
          continue;
        }
        for (const specifier of browserResolvedSpecifiers(
          readFileSync(resolve(src, entry), "utf8"),
        )) {
          if (!specifier.startsWith(".") && !specifier.startsWith("/")) {
            specifiers.add(specifier);
          }
        }
      }
    }
    // Guard the walk: the UI package imports the engine by bare specifier in
    // several modules, so an engine-less set means the walk found nothing and the
    // loop below would pass forever.
    expect([...specifiers]).toContain("@cplieger/web-terminal-engine");

    const html = readStaticAsset("index.html");
    const map = /<script\b[^>]*type=["']importmap["'][^>]*>([\s\S]*?)<\/script\s*>/i.exec(html);
    const parsed: unknown = JSON.parse(map?.[1] ?? "null");
    const keys = Object.keys((parsed as { imports?: Record<string, string> })?.imports ?? {});
    for (const specifier of specifiers) {
      expect(
        keys.some((key) => key === specifier || (key.endsWith("/") && specifier.startsWith(key))),
        `no importmap entry in static/index.html resolves ${specifier}, which the vendored library graph imports`,
      ).toBe(true);
    }
  });
});

describe("the attention icon variants app.ts opts into are actually served", () => {
  // app.ts passes attentionIcons: true, which is a PROMISE to the UI library that
  // three variants of every icon link exist. The library cannot check it: the
  // files live in this repo, the dot's colour comes from this app's theme, and the
  // library derives the URLs by a naming convention rather than reading a map. So
  // the consequence of breaking the promise is a BLANK tab icon, and this test is
  // the only thing standing between a renamed icon and that. Its sibling in
  // app.test.ts pins the COLOUR of the dot each variant paints; this half pins
  // that the files are served at all, which is a directory listing and therefore
  // lives here.
  //
  // The variant names are derived here the same way the library derives them
  // (insert -<variant> after the `favicon` token, keep the extension), rather than
  // listed literally, so a test that passes cannot be reading a stale list.
  const VARIANTS = ["input", "done", "alert"] as const;

  function variantOf(href: string, variant: string): string {
    return href.replace(/(^|\/)favicon(?=[-.])/, `$1favicon-${variant}`);
  }

  it("serves every variant of every icon link declared in index.html", () => {
    const html = readStaticAsset("index.html");
    const hrefs = [...html.matchAll(/<link\s+rel="icon"[^>]*href="([^"]+)"/g)].map((m) => m[1]!);
    // Guard the guard: a regex that matched nothing would make this test vacuous
    // and it would pass on a page with no icons at all.
    expect(hrefs.length).toBeGreaterThanOrEqual(3);

    const served = new Set(readdirSync(resolve(fixtureRoot(), "../static")));
    for (const href of hrefs) {
      const base = href.replace(/^\//, "");
      expect(served, `base icon ${base}`).toContain(base);
      for (const variant of VARIANTS) {
        const name = variantOf(base, variant);
        // A variant that equals its base means the rename convention did not
        // apply, so the library would leave that link alone and the dot would
        // silently never appear on it.
        expect(name, `${base} -> ${variant}`).not.toBe(base);
        expect(served, `variant ${name}`).toContain(name);
      }
    }
  });
});
