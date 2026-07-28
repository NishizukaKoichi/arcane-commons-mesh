import {
  ArchiveRestore,
  Boxes,
  Check,
  ChevronRight,
  CircleGauge,
  CloudCog,
  Database,
  FileLock2,
  FolderPlus,
  Globe2,
  HardDrive,
  Languages,
  LockKeyhole,
  Menu,
  Network,
  Plus,
  Settings,
  ShieldCheck,
  Trash2,
  Users,
  Vote
} from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";

type Page = "dashboard" | "vault" | "storage" | "community" | "recovery";
type Language = "ja" | "en";

const labels = {
  ja: {
    dashboard: "概要",
    vault: "保管庫",
    storage: "保存を提供",
    community: "共同体",
    recovery: "復旧と設定"
  },
  en: {
    dashboard: "Overview",
    vault: "Vault",
    storage: "Provide storage",
    community: "Community",
    recovery: "Recovery & settings"
  }
} satisfies Record<Language, Record<Page, string>>;

type StoredFile = {
  fileId: string;
  name: string;
  size: string;
  copies: string;
  modified: string;
  deleted?: boolean;
};

type DesktopFileRecord = {
  fileId: string;
  name: string;
  sizeBytes: number;
  safeReplicas: string;
  deleted: boolean;
};

type LocalMeshStatus = {
  connected: boolean;
  healthyNodes: number;
  totalNodes: number;
};

function displayDesktopFiles(files: DesktopFileRecord[]): StoredFile[] {
  return files.map((file) => ({
    fileId: file.fileId,
    name: file.name,
    size: formatBytes(file.sizeBytes),
    copies: file.safeReplicas,
    modified: file.deleted ? "削除予約中" : "保存済み",
    deleted: file.deleted
  }));
}

export function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [language, setLanguage] = useState<Language>("ja");
  const [onboarded, setOnboarded] = useState(false);
  const [checkingVault, setCheckingVault] = useState(true);
  const [hasExistingVault, setHasExistingVault] = useState(false);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [sessionPassphrase, setSessionPassphrase] = useState("");
  const [files, setFiles] = useState<StoredFile[]>([]);
  const [providerPath, setProviderPath] = useState("");
  const [providerEnabled, setProviderEnabled] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<StoredFile | null>(null);
  const [notice, setNotice] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const [mesh, setMesh] = useState<LocalMeshStatus>({
    connected: false,
    healthyNodes: 0,
    totalNodes: 3
  });
  const [connectingMesh, setConnectingMesh] = useState(false);

  useEffect(() => {
    if (!isTauri()) {
      setCheckingVault(false);
      return;
    }
    invoke<{ hasVault: boolean }>("desktop_status")
      .then((status) => setHasExistingVault(status.hasVault))
      .catch((reason) => setNotice(String(reason)))
      .finally(() => setCheckingVault(false));
  }, []);

  useEffect(() => {
    if (!onboarded || !isTauri()) return;
    invoke<LocalMeshStatus>("local_mesh_status")
      .then(setMesh)
      .catch(() => setMesh({ connected: false, healthyNodes: 0, totalNodes: 3 }));
  }, [onboarded]);

  if (checkingVault) {
    return <main className="onboarding"><p>既存の保管庫を確認しています…</p></main>;
  }

  if (hasExistingVault && !onboarded) {
    return (
      <UnlockVault
        onUnlock={(passphrase, storedFiles) => {
          setSessionPassphrase(passphrase);
          setFiles(storedFiles);
          setOnboarded(true);
        }}
      />
    );
  }

  if (!onboarded) {
    return (
      <Onboarding
        recoverySaved={recoverySaved}
        onRecoverySaved={(passphrase) => {
          setRecoverySaved(true);
          setSessionPassphrase(passphrase);
        }}
        onComplete={() => {
          setHasExistingVault(true);
          setOnboarded(true);
        }}
        onImported={(passphrase, recoveredFiles) => {
          setSessionPassphrase(passphrase);
          setFiles(recoveredFiles);
          setHasExistingVault(true);
          setOnboarded(true);
        }}
      />
    );
  }

  const nav = (["dashboard", "vault", "storage", "community", "recovery"] as Page[]).map(
    (item) => ({
      id: item,
      label: labels[language][item],
      icon:
        item === "dashboard"
          ? CircleGauge
          : item === "vault"
            ? FileLock2
            : item === "storage"
              ? HardDrive
              : item === "community"
                ? Users
                : Settings
    })
  );

  return (
    <div className="app-shell">
      <aside className={mobileNav ? "sidebar is-open" : "sidebar"}>
        <div className="brand">
          <div className="brand-mark" aria-hidden="true"><Network size={22} /></div>
          <div><strong>魔法網</strong><span>Arcane Commons Mesh</span></div>
        </div>
        <nav aria-label="主な画面">
          {nav.map(({ id, label, icon: Icon }) => (
            <button
              className={page === id ? "nav-item active" : "nav-item"}
              key={id}
              onClick={() => {
                setPage(id);
                setMobileNav(false);
              }}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className={mesh.connected ? "network-status is-connected" : "network-status"}>
          <span className="status-dot" />
          <div>
            <strong>{mesh.connected ? `${mesh.healthyNodes} / ${mesh.totalNodes} 拠点 接続中` : "3拠点ネットワーク"}</strong>
            <span>{mesh.connected ? "暗号化通信で保存します" : "このMacの検証拠点へ接続"}</span>
          </div>
          {!mesh.connected && (
            <button
              className="network-connect"
              disabled={connectingMesh}
              onClick={async () => {
                if (!isTauri()) {
                  setNotice("デスクトップアプリで接続できます");
                  return;
                }
                setConnectingMesh(true);
                try {
                  const status = await invoke<LocalMeshStatus>("connect_local_mesh", {
                    root: null
                  });
                  setMesh(status);
                  setNotice(`${status.healthyNodes}拠点へ安全に接続しました`);
                } catch (reason) {
                  setNotice(String(reason));
                } finally {
                  setConnectingMesh(false);
                }
              }}
            >
              {connectingMesh ? "確認中…" : "接続"}
            </button>
          )}
        </div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileNav(!mobileNav)} aria-label="メニュー">
            <Menu size={20} />
          </button>
          <div className="breadcrumb">ローカル検証環境 <ChevronRight size={14} /> {labels[language][page]}</div>
          <button
            className="language-button"
            onClick={() => setLanguage(language === "ja" ? "en" : "ja")}
          >
            <Languages size={16} /> {language === "ja" ? "EN" : "日本語"}
          </button>
        </header>
        <div className="page-enter" key={page}>
          {page === "dashboard" && <Dashboard files={files} mesh={mesh} onNavigate={setPage} />}
          {page === "vault" && (
            <Vault
              files={files}
              passphrase={sessionPassphrase}
              onAdded={(file) => setFiles((current) => [file, ...current])}
              onDelete={(file) => setDeleteTarget(file)}
              onRestore={async (file) => {
                if (!isTauri()) {
                  setNotice("ブラウザ表示では復元ファイルを書き出しません");
                  return;
                }
                const result = await invoke<{ path: string }>("restore_vault_file", {
                  fileId: file.fileId,
                  passphrase: sessionPassphrase
                });
                setNotice(`復元先: ${result.path}`);
              }}
            />
          )}
          {page === "storage" && (
            <ProvideStorage
              path={providerPath}
              enabled={providerEnabled}
              onPath={setProviderPath}
              onEnabled={setProviderEnabled}
            />
          )}
          {page === "community" && <Community />}
          {page === "recovery" && (
            <Recovery language={language} passphrase={sessionPassphrase} onNotice={setNotice} />
          )}
        </div>
      </main>
      {deleteTarget && (
        <ConfirmDialog
          fileName={deleteTarget.name}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={async () => {
            if (isTauri()) {
              await invoke("delete_vault_file", {
                fileId: deleteTarget.fileId,
                passphrase: sessionPassphrase
              });
            }
            setFiles((current) =>
              current.map((file) =>
                file.fileId === deleteTarget.fileId
                  ? { ...file, copies: "削除予約・30日間復元可", deleted: true }
                  : file
              )
            );
            setDeleteTarget(null);
            setNotice("30日保持の削除予約を記録しました");
          }}
        />
      )}
      {notice && <div className="inline-warning" role="status">{notice}</div>}
    </div>
  );
}

function UnlockVault({
  onUnlock
}: {
  onUnlock: (passphrase: string, files: StoredFile[]) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");
  const unlock = async () => {
    setError("");
    try {
      await invoke<number>("gc_vault", { passphrase });
      const storedFiles = await invoke<DesktopFileRecord[]>("list_vault_files", { passphrase });
      onUnlock(passphrase, displayDesktopFiles(storedFiles));
    } catch (reason) {
      setError(`保管庫を開けませんでした: ${String(reason)}`);
    }
  };
  return (
    <main className="onboarding">
      <section className="onboarding-copy">
        <div className="brand onboarding-brand"><div className="brand-mark"><Network size={22} /></div><strong>魔法網</strong></div>
        <p className="eyebrow">既存の保管庫</p>
        <h1>保管庫を開く。</h1>
        <p className="intro">この端末にある暗号化カタログを読み込みます。新しい保管庫で上書きはしません。</p>
      </section>
      <section className="onboarding-form" aria-labelledby="unlock-title">
        <h2 id="unlock-title">復旧パスフレーズ</h2>
        <label>
          パスフレーズ
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
          />
        </label>
        <button className="primary-button" disabled={passphrase.length < 12} onClick={unlock}>
          保管庫を開く <ChevronRight size={17} />
        </button>
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </main>
  );
}

function Onboarding({
  recoverySaved,
  onRecoverySaved,
  onComplete,
  onImported
}: {
  recoverySaved: boolean;
  onRecoverySaved: (passphrase: string) => void;
  onComplete: () => void;
  onImported: (passphrase: string, files: StoredFile[]) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [exportPath, setExportPath] = useState("");
  const [error, setError] = useState("");
  const [importPath, setImportPath] = useState("");
  const [sourceRoots, setSourceRoots] = useState("");
  const saveRecovery = async () => {
    setError("");
    try {
      if (isTauri()) {
        const result = await invoke<{ path: string }>("create_recovery_kit", { passphrase });
        setExportPath(result.path);
      } else {
        setExportPath("ブラウザ表示では書き出しを行いません");
      }
      onRecoverySaved(passphrase);
      setPassphrase("");
    } catch (reason) {
      setError(String(reason));
    }
  };
  const importRecovery = async () => {
    setError("");
    try {
      if (!isTauri()) {
        throw new Error("ブラウザ表示では復旧を実行できません");
      }
      const roots = sourceRoots
        .split(/\r?\n|,/)
        .map((value) => value.trim())
        .filter(Boolean);
      const recoveredFiles = await invoke<DesktopFileRecord[]>("import_recovery_kit", {
        recoveryPath: importPath,
        sourceRoots: roots,
        passphrase
      });
      onImported(passphrase, displayDesktopFiles(recoveredFiles));
    } catch (reason) {
      setError(String(reason));
    }
  };
  return (
    <main className="onboarding">
      <section className="onboarding-copy">
        <div className="brand onboarding-brand"><div className="brand-mark"><Network size={22} /></div><strong>魔法網</strong></div>
        <p className="eyebrow">最初の保管庫</p>
        <h1>大切なものを、<br />自分の鍵で守る。</h1>
        <p className="intro">このv0.1デスクトップではファイルを端末内で暗号化し、同じ端末上の独立したローカル保存領域へ複製します。</p>
        <div className="privacy-promise"><ShieldCheck size={22} /><span>共同体ノードへの実接続はCLIのローカル複数プロセス検証に限定されています。</span></div>
      </section>
      <section className="onboarding-form" aria-labelledby="setup-title">
        <p className="step-count">手順 1 / 3</p>
        <h2 id="setup-title">復旧ファイルを作成</h2>
        <p>端末を失ったときに保管庫を取り戻すための、暗号化されたファイルです。</p>
        <label>
          復旧パスフレーズ
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            placeholder="長く、他で使っていない言葉"
          />
        </label>
        <button
          className={recoverySaved ? "secondary-action complete" : "secondary-action"}
          disabled={passphrase.length < 12 || recoverySaved}
          onClick={() => void saveRecovery()}
        >
          {recoverySaved ? <Check size={18} /> : <ArchiveRestore size={18} />}
          {recoverySaved ? "復旧ファイルを保存しました" : "復旧ファイルを保存"}
        </button>
        <div className="settings-list">
          <label>
            既存の復旧ファイル
            <input
              value={importPath}
              onChange={(event) => setImportPath(event.target.value)}
              placeholder="/Volumes/Backup/owner.acm-recovery"
            />
          </label>
          <label>
            保存ノードフォルダ（1行に1つ）
            <textarea
              value={sourceRoots}
              onChange={(event) => setSourceRoots(event.target.value)}
              placeholder={"/Volumes/Node-A/storage\n/Volumes/Node-B/storage\n/Volumes/Node-C/storage"}
            />
          </label>
          <button
            className="secondary-action"
            disabled={passphrase.length < 12 || !importPath || !sourceRoots.trim()}
            onClick={() => void importRecovery()}
          >
            復旧ファイルから取り戻す
          </button>
        </div>
        <button className="primary-action" disabled={!recoverySaved} onClick={onComplete}>
          保管庫を作成 <ChevronRight size={18} />
        </button>
        {!recoverySaved && <p className="form-note">復旧ファイルを保存すると次へ進めます。</p>}
        {exportPath && <p className="form-note" role="status">保存先: {exportPath}</p>}
        {error && <p className="inline-warning" role="alert">{error}</p>}
      </section>
    </main>
  );
}

function Dashboard({
  files,
  mesh,
  onNavigate
}: {
  files: StoredFile[];
  mesh: LocalMeshStatus;
  onNavigate: (page: Page) => void;
}) {
  return (
    <section className="content">
      <PageTitle eyebrow="今日の状態" title="概要" action={<button className="primary-action compact" onClick={() => onNavigate("vault")}><Plus size={17} /> ファイルを追加</button>} />
      <div className="safety-line">
        <div className="safety-orb"><ShieldCheck size={30} /></div>
        <div><p>{files.length ? "暗号化複製は正常です" : "保管庫は空です"}</p><strong>{mesh.connected ? "3つの独立した保存拠点へ暗号化して送ります" : "ファイルを追加すると端末内で暗号化して保存します"}</strong></div>
        <span className="last-backup">{files.length ? "最終バックアップ たった今" : "バックアップなし"}</span>
      </div>
      <div className="metric-row">
        <Metric label="ファイル" value={String(files.length)} detail="暗号化済み" />
        <Metric label="保存拠点" value={mesh.connected ? `${mesh.healthyNodes} / ${mesh.totalNodes}` : "未接続"} detail="同一Mac内・独立プロセス" />
        <Metric label="共有容量" value="—" detail="調整API未接続" />
      </div>
      <div className="split-section">
        <section>
          <SectionHeading title="最近の保管" link="保管庫を開く" onClick={() => onNavigate("vault")} />
          <div className="file-list">
            {files.length ? files.slice(0, 2).map((file) => <FileRow file={file} key={file.fileId} />) : <p className="form-note">まだファイルはありません。</p>}
          </div>
        </section>
        <section>
          <SectionHeading title="ローカル保存領域" link="管理" onClick={() => onNavigate("storage")} />
          <div className="node-list">
            <NodeRow name="このMac / 拠点 A" state={mesh.healthyNodes >= 1 ? "接続中" : "停止"} usage="暗号化断片のみ" warning={mesh.healthyNodes < 1} />
            <NodeRow name="このMac / 拠点 B" state={mesh.healthyNodes >= 2 ? "接続中" : "停止"} usage="暗号化断片のみ" warning={mesh.healthyNodes < 2} />
            <NodeRow name="このMac / 拠点 C" state={mesh.healthyNodes >= 3 ? "接続中" : "停止"} usage="暗号化断片のみ" warning={mesh.healthyNodes < 3} />
          </div>
        </section>
      </div>
    </section>
  );
}

function Vault({
  files,
  passphrase,
  onAdded,
  onRestore,
  onDelete
}: {
  files: StoredFile[];
  passphrase: string;
  onAdded: (file: StoredFile) => void;
  onRestore: (file: StoredFile) => Promise<void>;
  onDelete: (file: StoredFile) => void;
}) {
  const [sourcePath, setSourcePath] = useState("");
  const [error, setError] = useState("");
  const addFile = async () => {
    setError("");
    try {
      const result = isTauri()
        ? await invoke<{ fileId: string; name: string; sizeBytes: number; safeReplicas: string; deleted: boolean }>(
            "add_vault_file",
            { sourcePath, passphrase }
          )
        : {
            fileId: `browser-${Date.now()}`,
            name: sourcePath.split("/").pop() || "選択したファイル",
            sizeBytes: 0,
            safeReplicas: "3/3",
            deleted: false
          };
      onAdded({
        fileId: result.fileId,
        name: result.name,
        size: formatBytes(result.sizeBytes),
        copies: result.safeReplicas,
        modified: "たった今",
        deleted: result.deleted
      });
      setSourcePath("");
    } catch (reason) {
      setError(String(reason));
    }
  };
  return (
    <section className="content">
      <PageTitle eyebrow="暗号化して分散保管" title="保管庫" action={<button className="primary-action compact" disabled={!sourcePath} onClick={() => void addFile()}><FolderPlus size={17} /> ファイルを追加</button>} />
      <label className="drop-zone"><CloudCog size={28} /><div><strong>追加するファイルの場所</strong><span>元のファイル名と中身は端末の外へ出ません</span></div><input aria-label="追加するファイルの場所" value={sourcePath} onChange={(event) => setSourcePath(event.target.value)} placeholder="/Users/.../写真.jpg" /></label>
      {error && <div className="inline-warning" role="alert">{error}</div>}
      <div className="table-heading"><span>名前</span><span>容量</span><span>安全な複製</span><span>更新</span><span /></div>
      <div className="file-table">
        {files.map((file) => (
          <div className="file-table-row" key={file.fileId}>
            <span className="file-name"><FileLock2 size={18} />{file.name}</span>
            <span>{file.size}</span>
            <span className={file.copies === "3/3" ? "copy-safe" : "copy-warning"}>{file.copies}</span>
            <span>{file.modified}</span>
            <span><button className="icon-button" aria-label={`${file.name}を復元`} onClick={() => void onRestore(file)}><ArchiveRestore size={17} /></button>{!file.deleted && <button className="icon-button danger" aria-label={`${file.name}を削除`} onClick={() => onDelete(file)}><Trash2 size={17} /></button>}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ProvideStorage({
  path,
  enabled,
  onPath,
  onEnabled
}: {
  path: string;
  enabled: boolean;
  onPath: (path: string) => void;
  onEnabled: (enabled: boolean) => void;
}) {
  const [error, setError] = useState("");
  const toggleProvider = async () => {
    const next = !enabled;
    setError("");
    try {
      if (isTauri()) {
        await invoke("configure_storage", {
          root: path,
          enabled: next,
          quotaBytes: 10 * 1024 * 1024 * 1024
        });
      }
      onEnabled(next);
    } catch (reason) {
      setError(String(reason));
    }
  };
  return (
    <section className="content narrow-content">
      <PageTitle eyebrow="共同体へ余白を貸す" title="保存を提供" />
      <div className="provider-status">
        <div><p>このMacの保存領域設定</p><strong>{enabled ? "設定済み" : "未設定"}</strong></div>
        <button
          role="switch"
          aria-checked={enabled}
          className={enabled ? "switch on" : "switch"}
          disabled={!path}
          onClick={() => void toggleProvider()}
        ><span /></button>
      </div>
      <div className="settings-list">
        <label className="setting-row">
          <span><Database size={19} /><span><strong>専用フォルダ</strong><small>選択した場所だけを使用します</small></span></span>
          <input value={path} onChange={(event) => onPath(event.target.value)} placeholder="フォルダを選択" />
        </label>
        <label className="setting-row">
          <span><HardDrive size={19} /><span><strong>提供上限</strong><small>最低20 GBの空きを残します</small></span></span>
          <select defaultValue="10"><option value="10">10 GB</option><option value="25">25 GB</option><option value="50">50 GB</option></select>
        </label>
        <label className="setting-row">
          <span><CircleGauge size={19} /><span><strong>通信速度</strong><small>ほかの作業を妨げない上限</small></span></span>
          <select defaultValue="5"><option value="2">2 MiB/s</option><option value="5">5 MiB/s</option><option value="10">10 MiB/s</option></select>
        </label>
      </div>
      {!path && <div className="inline-warning">専用フォルダを選ぶまで、保存提供は開始できません。</div>}
      {error && <div className="inline-warning" role="alert">{error}</div>}
      <div className="audit-summary"><ShieldCheck size={21} /><div><strong>ノードサービス未起動</strong><span>この画面は保存先と上限を記録します。共同体への登録・提供開始はまだ行いません。</span></div></div>
    </section>
  );
}

function Community() {
  return (
    <section className="content">
      <PageTitle eyebrow="未接続" title="共同体" />
      <div className="community-summary"><div><strong>—</strong><span>会員</span></div><div><strong>—</strong><span>保存拠点</span></div><div><strong>—</strong><span>障害領域</span></div></div>
      <div className="split-section">
        <section>
          <SectionHeading title="会員と加入申請" link="すべて表示" />
          <div className="join-request"><div><strong>調整APIへの接続が必要です</strong><span>会員や加入申請の実データは、接続後に表示されます。</span></div></div>
        </section>
        <section>
          <SectionHeading title="提案と投票" link="提案を作る" />
          <div className="proposal"><div className="proposal-icon"><Vote size={20} /></div><div><strong>投票データはありません</strong><span>共同体へ接続すると提案を取得します。</span></div></div>
          <p className="governance-note">保存容量や共有容量によって、投票の重みは変わりません。</p>
        </section>
      </div>
    </section>
  );
}

function Recovery({
  language,
  passphrase,
  onNotice
}: {
  language: Language;
  passphrase: string;
  onNotice: (notice: string) => void;
}) {
  const diagnostics = useMemo(() => ["アプリのバージョン", "接続状態", "匿名化したエラー履歴"], []);
  return (
    <section className="content narrow-content">
      <PageTitle eyebrow="持ち出せる仕組み" title="復旧と設定" />
      <div className="recovery-callout"><LockKeyhole size={25} /><div><strong>復旧ファイルはこの端末だけで作られます</strong><span>運営者や共同体から復旧パスフレーズを確認することはできません。</span></div><button className="secondary-action compact" onClick={() => {
        if (!isTauri()) {
          onNotice("ブラウザ表示では復旧ファイルを書き出しません");
          return;
        }
        void invoke<{ path: string }>("copy_recovery_kit", { passphrase })
          .then((result) => onNotice(`復旧ファイルを再出力しました: ${result.path}`))
          .catch((reason) => onNotice(String(reason)));
      }}><ArchiveRestore size={17} /> 再出力</button></div>
      <div className="settings-list">
        <div className="setting-row"><span><Globe2 size={19} /><span><strong>調整API</strong><small>http://127.0.0.1:8787</small></span></span><button className="text-button">変更</button></div>
        <div className="setting-row"><span><Boxes size={19} /><span><strong>Relay</strong><small>開発用・直接接続を優先</small></span></span><button className="text-button">変更</button></div>
        <div className="setting-row"><span><Languages size={19} /><span><strong>表示言語</strong><small>{language === "ja" ? "日本語" : "English"}</small></span></span></div>
      </div>
      <section className="diagnostics"><h2>診断情報を書き出す</h2><p>保存前に含まれる項目を確認できます。秘密やファイル名は含みません。</p><ul>{diagnostics.map((item) => <li key={item}><Check size={15} />{item}</li>)}</ul><button className="secondary-action compact">内容を確認</button></section>
    </section>
  );
}

function PageTitle({ eyebrow, title, action }: { eyebrow: string; title: string; action?: React.ReactNode }) {
  return <div className="page-title"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1></div>{action}</div>;
}
function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}
function SectionHeading({ title, link, onClick }: { title: string; link: string; onClick?: () => void }) {
  return <div className="section-heading"><h2>{title}</h2><button onClick={onClick}>{link}<ChevronRight size={15} /></button></div>;
}
function FileRow({ file }: { file: StoredFile }) {
  return <div className="file-row"><span className="file-icon"><FileLock2 size={18} /></span><div><strong>{file.name}</strong><span>{file.size} · {file.modified}</span></div><span className={file.copies === "3/3" ? "copy-safe" : "copy-warning"}>{file.copies}</span></div>;
}
function NodeRow({ name, state, usage, warning = false }: { name: string; state: string; usage: string; warning?: boolean }) {
  return <div className="node-row"><span className={warning ? "node-pulse warning" : "node-pulse"} /><div><strong>{name}</strong><span>{usage}</span></div><span>{state}</span></div>;
}
function ConfirmDialog({ fileName, onCancel, onConfirm }: { fileName: string; onCancel: () => void; onConfirm: () => void }) {
  return <div className="dialog-backdrop" role="presentation"><div className="dialog" role="dialog" aria-modal="true" aria-labelledby="delete-title"><div className="danger-symbol"><Trash2 size={22} /></div><h2 id="delete-title">「{fileName}」を削除しますか？</h2><p>30日間は過去の版から復元できます。保存拠点の暗号化データは、その後の整理まで残る場合があります。</p><div className="dialog-actions"><button className="secondary-action compact" onClick={onCancel}>キャンセル</button><button className="danger-action" onClick={onConfirm}>削除する</button></div></div></div>;
}

function isTauri() {
  return "__TAURI_INTERNALS__" in window;
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}
