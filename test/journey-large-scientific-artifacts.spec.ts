// Copyright (C) 2026-2026 Huawei Technologies Co., Ltd
// Licensed under the Apache License, Version 2.0 (the "License");

import { expect } from "@playwright/test";

import { test } from "./helpers/e2e.ts";
import {
  artifactTree,
  cleanupJourney,
  createProjectAndSession,
  openProjectSession,
  scriptedModel,
  sendUserMessage,
  waitForRunTerminal,
} from "./helpers/journeys.ts";

test.describe("journey-large-scientific-artifacts.spec", { tag: ["@category:e2e", "@os:linux", "@arch:amd64", "@model:mock", "@sandbox:bubblewrap"] }, () => {
  /**
   * E2E-META
   * Purpose: A researcher can read a very long source line and open a large numeric CSV and structure JSON without losing their results.
   * Steps:
   *   1. Prepare an isolated Project/Session with a journey-owned local model stub.
   *   2. Ask the model to create an 8 MB single-line text file, a 130,000-row CSV, and an 80,000-atom structure JSON.
   *   3. Read the long text through read_file and confirm the bounded page and next-line continuation are visible.
   *   4. Open the CSV visualization workspace and confirm its complete row count appears.
   *   5. Open the structure artifact and confirm the bounded interactive atom preview appears.
   * Environment: Isolated local stack at E2E_BASE_URL with managed Python ready and a journey-owned Project/Session.
   * Type: mocked
   * LLM: journey-owned OpenAI-compatible HTTP stub on 127.0.0.1; one deterministic user turn.
   * WebSearch: none
   * PaperSources: none
   * MCP: none
   * OtherExternal: none — Python runs in the offline local sandbox and non-local browser requests are blocked.
   * Credentials: E2E_API_TOKEN for the isolated local API only; no external credentials.
   * CostSideEffects: no external cost; generated local files and temporary records are cleaned up in finally.
   */
  test("J24 超长文件与大型科学成果仍可查看", { tag: "@mocked" }, async ({ journey, page }) => {
    test.setTimeout(300_000);
    const marker = `J24-LARGE-ARTIFACTS-${Date.now()}`;
    const python = [
      "import json",
      "from pathlib import Path",
      "Path('results').mkdir(exist_ok=True)",
      "with Path('results/large.csv').open('w', encoding='utf-8') as output:",
      "    output.write('id,value\\n')",
      "    for index in range(130_000):",
      "        output.write(f'sample-{index},{index}\\n')",
      "atoms = [{'element': 'C', 'x': index, 'y': 0, 'z': 0} for index in range(80_000)]",
      "Path('results/large.structure.json').write_text(json.dumps({'atoms': atoms}), encoding='utf-8')",
      "Path('results/long-line.txt').write_text('A' * 8_000_000 + '\\nnext\\n', encoding='utf-8')",
      `print('${marker}')`,
    ].join("\n");
    const stub = await scriptedModel([[
      { arguments: { command: `python3 - <<'PY'\n${python}\nPY` }, tool: "run_shell" },
      { arguments: { path: "results/long-line.txt" }, tool: "read_file" },
      { arguments: { path: "results/long-line.txt", offset: 2 }, tool: "read_file" },
      { arguments: { path: "results/large.csv" }, tool: "declare_artifact" },
      { arguments: { path: "results/large.structure.json" }, tool: "declare_artifact" },
      { text: "The large CSV and structure are ready to inspect." },
    ]]);
    const fixture = await createProjectAndSession(page, {
      approvalMode: "always_allow",
      model: {
        apiToken: stub.apiToken,
        baseUrl: stub.baseUrl,
        model: stub.model,
        name: `J24 local model ${Date.now()}`,
      },
      projectName: `J24 large artifacts ${Date.now()}`,
      sessionTitle: `J24 large artifact session ${Date.now()}`,
    });

    journey.scenario({
      goal: "研究员完成一次分析后，能分页读取超长文本，并查看大型数据表和结构模型。",
      preconditions: [
        "隔离栈已启动，托管 Python 可用",
        "模型由旅程自己的本地 stub 驱动，并生成超长文本、CSV 与结构 JSON",
      ],
    });

    try {
      await journey.step("生成并声明大型成果", "运行完成，产物区列出两份成果。", async () => {
        await openProjectSession(page, fixture);
        const run = await sendUserMessage(page, fixture.session.id, "Create a large numeric table and molecular structure for inspection.");
        const terminal = await waitForRunTerminal(page, fixture.session.id, run.id);
        expect(terminal.status, terminal.error).toBe("completed");
        const tree = await artifactTree(page);
        await expect(tree.artifactCount).toHaveText("2", { timeout: 30_000 });
      });

      await journey.step("核对超长文本分页", "文件读取步骤显示截断提示，并能从下一行继续读取。", async () => {
        const reads = page.getByRole("region", { name: /^(Agent activity|Agent 活动)$/ })
          .locator("details.timeline-disclosure.tool")
          .filter({ hasText: "Called read_file" });
        await expect(reads).toHaveCount(2);
        const first = reads.nth(0);
        await first.locator(":scope > summary").click();
        await expect(first.locator(".timeline-content")).toContainText("Line 1 is wider than one page");
        await expect(first.locator(".timeline-content")).toContainText("Continue with read_file");
        const second = reads.nth(1);
        await second.locator(":scope > summary").click();
        await expect(second.locator(".timeline-content")).toContainText("lines 2-2 of 2");
        await expect(second.locator(".timeline-content")).toContainText("next");
      });

      await journey.step("打开大型 CSV", "可视化工作台显示全部 130,000 行，不出现打开失败。", async () => {
        const tree = await artifactTree(page);
        await tree.catalog.getByRole("button", { name: "Open results/large.csv" }).click();
        const artifact = page.getByRole("dialog", { name: "Artifact: results/large.csv" });
        await artifact.locator(".csv-artifact-launch").click();
        const workspace = page.locator(".csva-window");
        await expect(workspace.locator(".csva-source-strip")).toContainText("130,000", { timeout: 30_000 });
        await expect(workspace.locator(".csva-parse-error")).toHaveCount(0);
        await workspace.getByRole("button", { name: "Close CSV Visualization Workspace" }).click();
        await artifact.getByRole("button", { name: "Close artifact viewer" }).click();
      });

      await journey.step("打开大型结构 JSON", "结构预览显示 8,000 个代表性原子，不发生页面异常。", async () => {
        const tree = await artifactTree(page);
        await tree.catalog.getByRole("button", { name: "Open results/large.structure.json" }).click();
        const artifact = page.getByRole("dialog", { name: "Artifact: results/large.structure.json" });
        await expect(artifact.locator(".structure-viewer svg circle")).toHaveCount(8_000, { timeout: 30_000 });
      });
    } finally {
      await cleanupJourney(page, fixture);
      await stub.stop();
    }
  });
});
