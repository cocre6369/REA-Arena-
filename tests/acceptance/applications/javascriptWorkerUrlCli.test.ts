import { expect } from "vitest";

import type { JavaScriptApplicationGraph } from "../../../src/domain/javascript/javascriptApplicationGraph.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { analyzeJavaScriptDirectory } from "../../support/cli/javascriptApplication.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";

const workerReferences = (graph: JavaScriptApplicationGraph) =>
  graph.nodes
    .filter(({ kind }) => kind === "worker")
    .flatMap((node) =>
      node.observations.map(({ properties, evidence }) => ({
        source:
          evidence.location.available &&
          evidence.location.value.kind === "source-range"
            ? evidence.location.value.source
            : null,
        declared_specifier: properties.declared_specifier,
        expression: properties.expression,
        resolved_path: properties.resolved_path,
        mapped_paths: graph.edges
          .filter(
            ({ relation, source_node_id }) =>
              relation === "maps_to" && source_node_id === node.node_id,
          )
          .map(({ properties: edge }) => edge.resolved_path),
      })),
    );

cliTest(
  "resolves module-relative Worker URL constructors through the compiled CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-worker-module-url-");
    const cases = [
      {
        source: "nested/relative.mjs",
        expression: 'new Worker(new URL("./worker.js", import.meta.url));',
        specifier: "./worker.js",
        resolved: "nested/worker.js",
      },
      {
        source: "nested/parent.mjs",
        expression:
          'new Worker(new URL("../parent-worker.js", import.meta.url));',
        specifier: "../parent-worker.js",
        resolved: "parent-worker.js",
      },
      {
        source: "nested/dot-segments.mjs",
        expression:
          'new Worker(new URL("./child/.././worker.js", import.meta.url));',
        specifier: "./child/.././worker.js",
        resolved: "nested/worker.js",
      },
      {
        source: "nested/template.mjs",
        expression:
          "new Worker(new URL(`./template-worker.js`, import.meta.url));",
        specifier: "./template-worker.js",
        resolved: "nested/template-worker.js",
      },
      {
        source: "nested/space.mjs",
        expression:
          'new Worker(new URL("./space%20worker.js?worker=1#entry", import.meta.url));',
        specifier: "./space%20worker.js?worker=1#entry",
        resolved: "nested/space worker.js",
      },
      {
        source: "nested/percent.mjs",
        expression:
          'new Worker(new URL("./percent%2520worker.js", import.meta.url));',
        specifier: "./percent%2520worker.js",
        resolved: "nested/percent%20worker.js",
      },
      ...["?value=", "#value="].map((suffix, index) => {
        const specifier = `./worker.js${suffix}%2F%2E%5C%00%FF\\\0`;
        return {
          source: `nested/suffix-${index}.mjs`,
          expression: `new Worker(new URL(${JSON.stringify(specifier)}, import.meta.url));`,
          specifier,
          resolved: "nested/worker.js",
        };
      }),
      {
        source: "bundled/entry.mjs",
        expression:
          'self.webpackChunkdemo.push([[1], {1: function(module, exports, require) { new Worker(new URL("./worker.js", import.meta.url)); }, "./worker.js": function(module) { module.exports = 42; }}]);',
        specifier: "./worker.js",
        resolved: "bundled/worker.js",
      },
      {
        source: "nested/literal.mjs",
        expression: 'new Worker("./literal-worker.js");',
        specifier: "./literal-worker.js",
        resolved: "nested/literal-worker.js",
      },
    ];
    await writeFixtureFiles(root, {
      ...Object.fromEntries(
        cases.flatMap(({ source, expression, resolved }) => [
          [source, expression],
          [resolved, `self.postMessage(${JSON.stringify(resolved)});`],
        ]),
      ),
      "nested/percent worker.js": "self.postMessage('double-decoding decoy');",
    });

    const result = await analyzeJavaScriptDirectory("CLI", cli, root);
    expect(result.statistics.parse_failures).toBe(0);
    expect(workerReferences(result.graph)).toEqual(
      expect.arrayContaining(
        cases.map(({ source, specifier, resolved }) => ({
          source,
          declared_specifier: specifier,
          expression: null,
          resolved_path: resolved,
          mapped_paths: [resolved],
        })),
      ),
    );
    expect(workerReferences(result.graph)).toHaveLength(cases.length);
    expect(result.graph.nodes).toContainEqual(
      expect.objectContaining({
        kind: "javascript-module",
        observations: expect.arrayContaining([
          expect.objectContaining({
            properties: expect.objectContaining({ module_key: "./worker.js" }),
          }),
        ]),
      }),
    );
  },
);

cliTest(
  "keeps unsupported Worker URL expressions and missing exact files unresolved through the CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-worker-url-unknown-");
    const expressions = {
      "dynamic-path.mjs": "new Worker(new URL(path, import.meta.url));",
      "dynamic-base.mjs": 'new Worker(new URL("./worker.js", base));',
      "shadowed.mjs":
        'function start(URL) { return new Worker(new URL("./worker.js", import.meta.url)); }',
      "call.mjs": 'new Worker(URL("./worker.js", import.meta.url));',
      "custom.mjs":
        'new Worker(new custom.URL("./worker.js", import.meta.url));',
      "extension.mjs":
        'new Worker(new URL("./extensionless", import.meta.url));',
      "directory.mjs": 'new Worker(new URL("./directory", import.meta.url));',
      "directory-dot.mjs":
        'new Worker(new URL("./worker.js/.", import.meta.url));',
      "directory-parent.mjs":
        'new Worker(new URL("./worker.js/child/..", import.meta.url));',
      "empty-segment.mjs":
        'new Worker(new URL("./child//../worker.js", import.meta.url));',
      "package.mjs":
        'new Worker(new URL("./package-worker", import.meta.url));',
      "external.mjs":
        'new Worker(new URL("https://example.test/worker.js", import.meta.url));',
      "empty.mjs": 'new Worker(new URL("", import.meta.url));',
      "query.mjs": 'new Worker(new URL("?worker=1", import.meta.url));',
      "whitespace.mjs":
        'new Worker(new URL(" ./worker.js ", import.meta.url));',
      "control.mjs": 'new Worker(new URL("./worker\\t.js", import.meta.url));',
      "leading-control.mjs":
        'new Worker(new URL("\\u0001./worker.js", import.meta.url));',
    };
    const knownSpecifiers: Readonly<Record<string, string>> = {
      "extension.mjs": "./extensionless",
      "directory.mjs": "./directory",
      "directory-dot.mjs": "./worker.js/.",
      "directory-parent.mjs": "./worker.js/child/..",
      "empty-segment.mjs": "./child//../worker.js",
      "package.mjs": "./package-worker",
      "external.mjs": "https://example.test/worker.js",
    };
    await writeFixtureFiles(root, {
      ...expressions,
      "worker.js": "self.postMessage('existing decoy');",
      "extensionless.js": "self.postMessage('extension decoy');",
      "directory/index.js": "self.postMessage('index decoy');",
      "package-worker/package.json": JSON.stringify({ main: "selected.js" }),
      "package-worker/selected.js": "self.postMessage('package main decoy');",
    });

    const result = await analyzeJavaScriptDirectory("CLI", cli, root);
    expect(result.statistics.parse_failures).toBe(0);
    const references = workerReferences(result.graph);
    expect(references).toHaveLength(Object.keys(expressions).length);
    for (const [source, expression] of Object.entries(expressions)) {
      const specifier = knownSpecifiers[source] ?? null;
      expect(references).toContainEqual(
        expect.objectContaining({
          source,
          declared_specifier: specifier,
          expression:
            specifier === null
              ? expression.slice(
                  expression.indexOf("new Worker("),
                  expression.lastIndexOf(";"),
                )
              : null,
          resolved_path: null,
          mapped_paths: [],
        }),
      );
    }
  },
);
