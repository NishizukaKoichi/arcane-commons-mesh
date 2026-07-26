import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
import { App } from "../src/App";

afterEach(() => {
  invokeMock.mockReset();
  delete (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
});

async function finishOnboarding() {
  const user = userEvent.setup();
  render(<App />);
  const complete = screen.getByRole("button", { name: /保管庫を作成/ });
  expect(complete).toBeDisabled();
  await user.type(screen.getByLabelText("復旧パスフレーズ"), "very long recovery phrase");
  await user.click(screen.getByRole("button", { name: "復旧ファイルを保存" }));
  expect(complete).toBeEnabled();
  await user.click(complete);
  return user;
}

describe("desktop safety flows", () => {
  it("cannot finish onboarding before recovery export", async () => {
    const user = userEvent.setup();
    render(<App />);
    const complete = screen.getByRole("button", { name: /保管庫を作成/ });
    expect(complete).toBeDisabled();
    await user.type(screen.getByLabelText("復旧パスフレーズ"), "short");
    expect(screen.getByRole("button", { name: "復旧ファイルを保存" })).toBeDisabled();
  });

  it("shows overview after recovery export", async () => {
    await finishOnboarding();
    expect(screen.getByText("保管庫は空です")).toBeInTheDocument();
    expect(screen.getByText("バックアップなし")).toBeInTheDocument();
  });

  it("requires a provider path before enabling storage", async () => {
    const user = await finishOnboarding();
    await user.click(screen.getByRole("button", { name: "保存を提供" }));
    const toggle = screen.getByRole("switch");
    expect(toggle).toBeDisabled();
    await user.type(screen.getByPlaceholderText("フォルダを選択"), "/dedicated/storage");
    expect(toggle).toBeEnabled();
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-checked", "true");
  });

  it("requires confirmation for delete and explains retention", async () => {
    const user = await finishOnboarding();
    await user.click(screen.getByRole("button", { name: "保管庫" }));
    await user.type(screen.getByLabelText("追加するファイルの場所"), "/private/家族写真.jpg");
    await user.click(screen.getByRole("button", { name: "ファイルを追加" }));
    await user.click(screen.getByRole("button", { name: "家族写真.jpgを削除" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText(/30日間は過去の版から復元/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "キャンセル" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("exposes language switching and non-weighted governance copy", async () => {
    const user = await finishOnboarding();
    await user.click(screen.getByRole("button", { name: "共同体" }));
    expect(screen.getByText(/投票の重みは変わりません/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "EN" }));
    expect(screen.getByRole("button", { name: "Community" })).toBeInTheDocument();
  });

  it("detects an existing vault and lists retained files after restart", async () => {
    (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {};
    invokeMock.mockImplementation((command: string) => {
      if (command === "desktop_status") return Promise.resolve({ hasVault: true });
      if (command === "gc_vault") return Promise.resolve(0);
      if (command === "list_vault_files") {
        return Promise.resolve([
          {
            fileId: "retained-file",
            name: "retained.txt",
            sizeBytes: 12,
            safeReplicas: "削除予約・30日間復元可",
            deleted: true
          }
        ]);
      }
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });
    const user = userEvent.setup();
    render(<App />);
    expect(await screen.findByText("既存の保管庫")).toBeInTheDocument();
    await user.type(screen.getByLabelText("パスフレーズ"), "very long recovery phrase");
    await user.click(screen.getByRole("button", { name: "保管庫を開く" }));
    expect(await screen.findByText("retained.txt")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "保管庫" }));
    expect(screen.getByRole("button", { name: "retained.txtを復元" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "retained.txtを削除" })).not.toBeInTheDocument();
  });

  it("imports a Recovery Kit through the Tauri recovery command", async () => {
    (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {};
    invokeMock.mockImplementation((command: string) => {
      if (command === "desktop_status") return Promise.resolve({ hasVault: false });
      if (command === "import_recovery_kit") {
        return Promise.resolve([
          {
            fileId: "recovered-file",
            name: "recovered.txt",
            sizeBytes: 20,
            safeReplicas: "3/3",
            deleted: false
          }
        ]);
      }
      return Promise.reject(new Error(`unexpected command: ${command}`));
    });
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("復旧ファイルを作成")).toBeInTheDocument());
    await user.type(screen.getByLabelText("復旧パスフレーズ"), "very long recovery phrase");
    await user.type(
      screen.getByLabelText("既存の復旧ファイル"),
      "/Volumes/Backup/owner.acm-recovery"
    );
    await user.type(
      screen.getByLabelText(/保存ノードフォルダ/),
      "/Volumes/Node-A/storage"
    );
    await user.click(screen.getByRole("button", { name: "復旧ファイルから取り戻す" }));
    expect(await screen.findByText("recovered.txt")).toBeInTheDocument();
  });
});
