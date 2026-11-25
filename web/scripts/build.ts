import { brotliCompressSync, constants as zlibConstants, gzipSync } from 'node:zlib';
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, extname, join, resolve } from 'node:path';
import { build, type BuildOptions, type Plugin } from 'esbuild';

const req = createRequire(import.meta.url);
const webDir = resolve(import.meta.dirname, '..');
const distDir = resolve(webDir, 'dist');

const rnwlBase = dirname(req.resolve('@hanzogui/react-native-web-lite/package.json'));
const rnwlEntry = `${rnwlBase}/dist/esm/index.js`;
const rnSvgEntry = `${dirname(req.resolve('@hanzogui/react-native-svg/package.json'))}/dist/esm/index.js`;
const guiPkgPath = req.resolve('@hanzo/gui/package.json');
const guiReq = createRequire(guiPkgPath);
const guiEntry = `${dirname(guiPkgPath)}/dist/esm/index.js`;
const guiCoreEntry = `${dirname(guiReq.resolve('@hanzogui/core/package.json'))}/dist/esm/index.js`;
const guiWebEntry = `${dirname(guiReq.resolve('@hanzogui/web/package.json'))}/dist/esm/index.js`;
const themeShim = resolve(webDir, 'src/theme-shim.ts');

export function createHanzoGuiPlugin(): Plugin {
  return {
    name: 'hanzo-gui-native-resolve',
    setup(b) {
      b.onResolve({ filter: /^@hanzogui\/core$/ }, () => ({ path: guiCoreEntry }));
      b.onResolve({ filter: /^@hanzogui\/web$/ }, () => ({ path: guiWebEntry }));
      b.onResolve({ filter: /^@hanzo\/gui$/ }, () => ({ path: guiEntry }));
      b.onResolve({ filter: /^react-native$/ }, () => ({ path: rnwlEntry }));
      b.onResolve({ filter: /^react-native-web$/ }, () => ({ path: rnwlEntry }));
      b.onResolve({ filter: /^react-native-svg$/ }, () => ({ path: rnSvgEntry }));
      b.onResolve({ filter: /^@hanzogui\/next-theme$/ }, () => ({ path: themeShim }));
      b.onResolve({ filter: /^react-native\/package\.json$/ }, () => ({
        path: req.resolve('@hanzogui/react-native-web-lite/package.json'),
      }));
      b.onResolve(
        { filter: /^react-native(?:-web)?\/dist\/(?:exports|modules)\/.*\/([^/]+)$/ },
        (args) => {
          const match = args.path.match(/\/([^/]+)$/);
          if (match) {
            return { path: `${rnwlBase}/dist/esm/${match[1]}` };
          }
          return undefined;
        },
      );
      b.onResolve(
        {
          filter:
            /^react-native\/(Libraries\/Utilities\/codegenNativeComponent|Libraries\/Utilities\/codegenNativeCommand)$/,
        },
        (args) => ({ path: `${rnwlBase}/${args.path.slice('react-native/'.length)}` }),
      );
      b.onResolve({ filter: /^@hanzo\/font\/css$/ }, () => ({
        path: req.resolve('@hanzo/font/css'),
      }));
    },
  };
}

export function renderHtml(opts: {
  readonly jsEntry: string;
  readonly cssEntries: readonly string[];
}): string {
  const cssLinks = opts.cssEntries
    .map((href) => `    <link rel="stylesheet" crossorigin href="${href}" />`)
    .join('\n');
  return `<!doctype html>
<html lang="en" class="dark t_dark" data-theme="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
    <meta name="color-scheme" content="dark light" />
    <title>Hanzo Cyber</title>
    <meta name="description" content="Autonomous security operations console backed by Hanzo Cyber Go runtime, Rust cyber-probe, and Hanzo IAM." />
${cssLinks}
  </head>
  <body>
    <div id="root"></div>
    <script>
      window.process = window.process || { env: { NODE_ENV: "production", GUI_TARGET: "web", TAMAGUI_TARGET: "web" } };
      window.global = window.global || window;
      (async () => {
        try {
          const r = await fetch('/config.json', { cache: 'no-store' });
          if (r.ok) window.__HANZO_CYBER_CONFIG__ = await r.json();
        } catch {}
        await import(${JSON.stringify(opts.jsEntry)});
      })();
    </script>
  </body>
</html>
`;
}

export function writeRuntimeConfig(): void {
  const cfg = {
    apiBase: process.env.CYBER_API_BASE || '',
    iamHost: process.env.CYBER_IAM_HOST || 'https://hanzo.id',
    ensoHost: process.env.CYBER_ENSO_HOST || 'https://api.hanzo.ai',
  };
  writeFileSync(join(distDir, 'config.json'), `${JSON.stringify(cfg, null, 2)}\n`);
}

export function createEsbuildOptions(): BuildOptions {
  return {
    entryPoints: { main: resolve(webDir, 'src/main.tsx') },
    bundle: true,
    format: 'esm',
    splitting: true,
    platform: 'browser',
    target: ['es2022'],
    outdir: join(distDir, 'assets'),
    publicPath: '/assets/',
    entryNames: '[name]-[hash]',
    chunkNames: 'chunks/[name]-[hash]',
    assetNames: 'media/[name]-[hash]',
    minify: true,
    sourcemap: 'external',
    metafile: true,
    jsx: 'automatic',
    conditions: ['browser', 'module', 'import', 'default'],
    mainFields: ['browser', 'module', 'main'],
    define: {
      'process.env.NODE_ENV': JSON.stringify('production'),
      'process.env.GUI_TARGET': JSON.stringify('web'),
      'process.env.TAMAGUI_TARGET': JSON.stringify('web'),
      __DEV__: 'false',
    },
    loader: {
      '.woff': 'file',
      '.woff2': 'file',
      '.ttf': 'file',
      '.otf': 'file',
      '.png': 'file',
      '.jpg': 'file',
      '.webp': 'file',
      '.svg': 'file',
    },
    plugins: [createHanzoGuiPlugin()],
  };
}

function precompress(dir: string): number {
  const compressible = new Set(['.html', '.js', '.css', '.json', '.svg']);
  let count = 0;
  const walk = (p: string) => {
    for (const entry of readdirSync(p)) {
      const full = join(p, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (compressible.has(extname(full)) && st.size > 1024 && st.size <= 8 * 1024 * 1024) {
        const raw = readFileSync(full);
        writeFileSync(`${full}.gz`, gzipSync(raw, { level: 6 }));
        writeFileSync(
          `${full}.br`,
          brotliCompressSync(raw, { params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 4 } }),
        );
        count++;
      }
    }
  };
  walk(dir);
  return count;
}

export async function runProductionBuild(): Promise<void> {
  const t0 = Date.now();
  rmSync(distDir, { recursive: true, force: true });
  mkdirSync(join(distDir, 'assets'), { recursive: true });

  const result = await build(createEsbuildOptions());

  const inputPaths = Object.keys(result.metafile?.inputs ?? {});
  for (const pkg of ['@hanzogui/web', '@hanzogui/core']) {
    const slug = pkg.replace('/', '+');
    const versions = new Set<string>();
    for (const p of inputPaths) {
      const m = p.match(new RegExp(`\\.pnpm/${slug.replace('+', '\\+')}@([^/_]+)`));
      if (m) versions.add(m[1]);
    }
    if (versions.size > 1) {
      throw new Error(`Duplicate ${pkg} versions bundled (${[...versions].join(', ')}).`);
    }
  }

  const outputs = Object.entries(result.metafile?.outputs ?? {});
  const entryOut = outputs.find(([, meta]) =>
    meta.entryPoint?.replace(/\\/g, '/').endsWith('src/main.tsx'),
  );
  if (!entryOut) {
    throw new Error('Could not find src/main.tsx entry in esbuild metafile outputs');
  }
  const [entryPath, entryMeta] = entryOut;
  const jsEntry = `/${entryPath.slice(entryPath.indexOf('assets/'))}`;
  const cssEntries: string[] = [];
  if (entryMeta.cssBundle) {
    cssEntries.push(`/${entryMeta.cssBundle.slice(entryMeta.cssBundle.indexOf('assets/'))}`);
  }
  for (const [outPath] of outputs) {
    if (!outPath.endsWith('.css')) continue;
    const rel = `/${outPath.slice(outPath.indexOf('assets/'))}`;
    if (!rel.startsWith('/assets/chunks/') && !cssEntries.includes(rel)) {
      cssEntries.push(rel);
    }
  }

  writeRuntimeConfig();
  writeFileSync(join(distDir, 'index.html'), renderHtml({ jsEntry, cssEntries }));
  const compressed = precompress(distDir);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
  console.log(
    `@hanzo/gui cyber build complete in ${elapsed}s -> ${distDir} (entry=${jsEntry}, css=${cssEntries.length}, precompressed=${compressed})`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runProductionBuild().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
