import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../src/App";

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
});
