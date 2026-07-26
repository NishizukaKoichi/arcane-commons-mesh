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
import { useMemo, useState } from "react";

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

const sampleFiles = [
  { name: "家族写真 2026", size: "1.8 GB", copies: "3/3", modified: "8分前" },
  { name: "研究ノート", size: "284 MB", copies: "3/3", modified: "昨日" },
  { name: "AIの記憶", size: "96 MB", copies: "2/3", modified: "2日前" }
];

export function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [language, setLanguage] = useState<Language>("ja");
  const [onboarded, setOnboarded] = useState(false);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [providerPath, setProviderPath] = useState("");
  const [providerEnabled, setProviderEnabled] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);

  if (!onboarded) {
    return (
      <Onboarding
        recoverySaved={recoverySaved}
        onRecoverySaved={() => setRecoverySaved(true)}
        onComplete={() => setOnboarded(true)}
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
        <div className="network-status">
          <span className="status-dot" />
          <div><strong>共同体に接続中</strong><span>4つの保存拠点</span></div>
        </div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileNav(!mobileNav)} aria-label="メニュー">
            <Menu size={20} />
          </button>
          <div className="breadcrumb">白樺の共同体 <ChevronRight size={14} /> {labels[language][page]}</div>
          <button
            className="language-button"
            onClick={() => setLanguage(language === "ja" ? "en" : "ja")}
          >
            <Languages size={16} /> {language === "ja" ? "EN" : "日本語"}
          </button>
        </header>
        <div className="page-enter" key={page}>
          {page === "dashboard" && <Dashboard onNavigate={setPage} />}
          {page === "vault" && <Vault onDelete={setDeleteTarget} />}
          {page === "storage" && (
            <ProvideStorage
              path={providerPath}
              enabled={providerEnabled}
              onPath={setProviderPath}
              onEnabled={setProviderEnabled}
            />
          )}
          {page === "community" && <Community />}
          {page === "recovery" && <Recovery language={language} />}
        </div>
      </main>
      {deleteTarget && (
        <ConfirmDialog
          fileName={deleteTarget}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={() => setDeleteTarget(null)}
        />
      )}
    </div>
  );
}

function Onboarding({
  recoverySaved,
  onRecoverySaved,
  onComplete
}: {
  recoverySaved: boolean;
  onRecoverySaved: () => void;
  onComplete: () => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  return (
    <main className="onboarding">
      <section className="onboarding-copy">
        <div className="brand onboarding-brand"><div className="brand-mark"><Network size={22} /></div><strong>魔法網</strong></div>
        <p className="eyebrow">最初の保管庫</p>
        <h1>大切なものを、<br />自分の鍵で守る。</h1>
        <p className="intro">ファイルはこの端末で暗号化され、共同体の三つの保存拠点へ分かれて保管されます。</p>
        <div className="privacy-promise"><ShieldCheck size={22} /><span>運営者や保存拠点に、ファイル名・中身・復号鍵は渡りません。</span></div>
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
          onClick={onRecoverySaved}
        >
          {recoverySaved ? <Check size={18} /> : <ArchiveRestore size={18} />}
          {recoverySaved ? "復旧ファイルを保存しました" : "復旧ファイルを保存"}
        </button>
        <button className="primary-action" disabled={!recoverySaved} onClick={onComplete}>
          保管庫を作成 <ChevronRight size={18} />
        </button>
        {!recoverySaved && <p className="form-note">復旧ファイルを保存すると次へ進めます。</p>}
      </section>
    </main>
  );
}

function Dashboard({ onNavigate }: { onNavigate: (page: Page) => void }) {
  return (
    <section className="content">
      <PageTitle eyebrow="今日の状態" title="概要" action={<button className="primary-action compact" onClick={() => onNavigate("vault")}><Plus size={17} /> ファイルを追加</button>} />
      <div className="safety-line">
        <div className="safety-orb"><ShieldCheck size={30} /></div>
        <div><p>保管庫は安全です</p><strong>すべてのファイルに必要な複製があります</strong></div>
        <span className="last-backup">最終バックアップ 8分前</span>
      </div>
      <div className="metric-row">
        <Metric label="使用中" value="2.18 GB" detail="論理容量" />
        <Metric label="安全な複製" value="3 / 3" detail="6.54 GBを分散保管" />
        <Metric label="今月の共有容量" value="68%" detail="残り 3.4 GiB相当" />
      </div>
      <div className="split-section">
        <section>
          <SectionHeading title="最近の保管" link="保管庫を開く" onClick={() => onNavigate("vault")} />
          <div className="file-list">
            {sampleFiles.slice(0, 2).map((file) => <FileRow file={file} key={file.name} />)}
          </div>
        </section>
        <section>
          <SectionHeading title="保存拠点" link="管理" onClick={() => onNavigate("storage")} />
          <div className="node-list">
            <NodeRow name="このMac" state="接続中" usage="1.6 / 10 GB" />
            <NodeRow name="Blue Mountains" state="接続中" usage="2.1 / 20 GB" />
            <NodeRow name="Kyoto Commons" state="低速" usage="2.8 / 15 GB" warning />
          </div>
        </section>
      </div>
    </section>
  );
}

function Vault({ onDelete }: { onDelete: (file: string) => void }) {
  return (
    <section className="content">
      <PageTitle eyebrow="暗号化して分散保管" title="保管庫" action={<button className="primary-action compact"><FolderPlus size={17} /> ファイルを追加</button>} />
      <div className="drop-zone" tabIndex={0}><CloudCog size={28} /><div><strong>ここへファイルやフォルダを追加</strong><span>元のファイル名と中身は端末の外へ出ません</span></div></div>
      <div className="table-heading"><span>名前</span><span>容量</span><span>安全な複製</span><span>更新</span><span /></div>
      <div className="file-table">
        {sampleFiles.map((file) => (
          <div className="file-table-row" key={file.name}>
            <span className="file-name"><FileLock2 size={18} />{file.name}</span>
            <span>{file.size}</span>
            <span className={file.copies === "3/3" ? "copy-safe" : "copy-warning"}>{file.copies}</span>
            <span>{file.modified}</span>
            <button className="icon-button danger" aria-label={`${file.name}を削除`} onClick={() => onDelete(file.name)}><Trash2 size={17} /></button>
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
  return (
    <section className="content narrow-content">
      <PageTitle eyebrow="共同体へ余白を貸す" title="保存を提供" />
      <div className="provider-status">
        <div><p>このMacの保存拠点</p><strong>{enabled ? "提供中" : "停止中"}</strong></div>
        <button
          role="switch"
          aria-checked={enabled}
          className={enabled ? "switch on" : "switch"}
          disabled={!path}
          onClick={() => onEnabled(!enabled)}
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
      <div className="audit-summary"><ShieldCheck size={21} /><div><strong>直近の確認は成功</strong><span>暗号化された保存データを3時間前に確認しました</span></div></div>
    </section>
  );
}

function Community() {
  return (
    <section className="content">
      <PageTitle eyebrow="白樺の共同体" title="共同体" action={<button className="secondary-action compact"><Users size={17} /> 招待を作る</button>} />
      <div className="community-summary"><div><strong>12</strong><span>会員</span></div><div><strong>4</strong><span>保存拠点</span></div><div><strong>3</strong><span>障害領域</span></div></div>
      <div className="split-section">
        <section>
          <SectionHeading title="会員と加入申請" link="すべて表示" />
          <div className="member-row"><span className="avatar">KN</span><div><strong>Koichi Nishizuka</strong><span>管理者・確認拠点</span></div><span className="quiet-badge">自分</span></div>
          <div className="member-row"><span className="avatar pale">AM</span><div><strong>Aiko Mori</strong><span>会員</span></div><span className="presence" /></div>
          <div className="join-request"><div><strong>1件の加入申請</strong><span>公開鍵を確認して承認してください</span></div><button className="secondary-action compact">確認</button></div>
        </section>
        <section>
          <SectionHeading title="提案と投票" link="提案を作る" />
          <div className="proposal"><div className="proposal-icon"><Vote size={20} /></div><div><strong>保存確認の頻度を6時間にする</strong><span>残り2日 · 8 / 12人が投票</span><div className="vote-bar"><span style={{ width: "72%" }} /></div></div></div>
          <p className="governance-note">保存容量や共有容量によって、投票の重みは変わりません。</p>
        </section>
      </div>
    </section>
  );
}

function Recovery({ language }: { language: Language }) {
  const diagnostics = useMemo(() => ["アプリのバージョン", "接続状態", "匿名化したエラー履歴"], []);
  return (
    <section className="content narrow-content">
      <PageTitle eyebrow="持ち出せる仕組み" title="復旧と設定" />
      <div className="recovery-callout"><LockKeyhole size={25} /><div><strong>復旧ファイルはこの端末だけで作られます</strong><span>運営者や共同体から復旧パスフレーズを確認することはできません。</span></div><button className="secondary-action compact"><ArchiveRestore size={17} /> 再出力</button></div>
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
function FileRow({ file }: { file: (typeof sampleFiles)[number] }) {
  return <div className="file-row"><span className="file-icon"><FileLock2 size={18} /></span><div><strong>{file.name}</strong><span>{file.size} · {file.modified}</span></div><span className={file.copies === "3/3" ? "copy-safe" : "copy-warning"}>{file.copies}</span></div>;
}
function NodeRow({ name, state, usage, warning = false }: { name: string; state: string; usage: string; warning?: boolean }) {
  return <div className="node-row"><span className={warning ? "node-pulse warning" : "node-pulse"} /><div><strong>{name}</strong><span>{usage}</span></div><span>{state}</span></div>;
}
function ConfirmDialog({ fileName, onCancel, onConfirm }: { fileName: string; onCancel: () => void; onConfirm: () => void }) {
  return <div className="dialog-backdrop" role="presentation"><div className="dialog" role="dialog" aria-modal="true" aria-labelledby="delete-title"><div className="danger-symbol"><Trash2 size={22} /></div><h2 id="delete-title">「{fileName}」を削除しますか？</h2><p>30日間は過去の版から復元できます。保存拠点の暗号化データは、その後の整理まで残る場合があります。</p><div className="dialog-actions"><button className="secondary-action compact" onClick={onCancel}>キャンセル</button><button className="danger-action" onClick={onConfirm}>削除する</button></div></div></div>;
}
