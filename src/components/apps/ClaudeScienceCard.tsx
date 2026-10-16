import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2, Play, Square } from "lucide-react";

import {
  claudeScienceApi,
  type ClaudeScienceStatus,
} from "@/lib/api/claudeScience";
import { Button } from "@/components/ui/button";

/**
 * Claude Science（原生 Windows）入口。
 *
 * 在 CC Switch 私有的隔离目录里生成托管虚拟登录，再把推理指向本地代理的
 * /claude-science 路由；真实的 Science 数据目录与登录不受影响。
 */
export function ClaudeScienceCard() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ClaudeScienceStatus | null>(null);
  const [busy, setBusy] = useState<"launch" | "stop" | null>(null);
  const [detail, setDetail] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setStatus(await claudeScienceApi.getStatus());
    } catch (cause) {
      setError(String(cause));
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const launch = async () => {
    setBusy("launch");
    setError(null);
    setDetail(null);
    try {
      const report = await claudeScienceApi.launch();
      setDetail(
        t("claudeScience.launched", {
          port: report.port,
          baseUrl: report.baseUrl,
        }),
      );
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(null);
      void refresh();
    }
  };

  const stop = async () => {
    setBusy("stop");
    setError(null);
    setDetail(null);
    try {
      await claudeScienceApi.stop();
      setDetail(t("claudeScience.stopped"));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(null);
      void refresh();
    }
  };

  const state = status?.installed
    ? status.hasVirtualLogin
      ? t("claudeScience.ready")
      : t("claudeScience.installedNoProfile")
    : status?.supported
      ? t("claudeScience.notInstalled")
      : t("claudeScience.unsupported");

  return (
    <div className="mt-4 rounded-panel border border-border bg-surface p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <div className="text-body font-medium">
            {t("claudeScience.title")}
          </div>
          <div className="text-caption text-fg-2">
            {status?.version
              ? t("claudeScience.version", { version: status.version })
              : state}
          </div>
          <div className="truncate text-caption text-fg-3">
            {status?.installed ? state : status?.message || state}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button
            variant="neutral"
            size="compact"
            disabled={!status?.installed || busy !== null}
            onClick={() => void launch()}
          >
            {busy === "launch" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {t("claudeScience.launch")}
          </Button>
          <Button
            variant="neutral"
            size="compact"
            disabled={busy !== null}
            onClick={() => void stop()}
          >
            {busy === "stop" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Square className="h-3.5 w-3.5" />
            )}
            {t("claudeScience.stop")}
          </Button>
        </div>
      </div>
      {detail && (
        <div className="mt-2 break-all text-caption text-fg-2">{detail}</div>
      )}
      {error && (
        <div className="mt-2 break-all text-caption text-red-500">{error}</div>
      )}
    </div>
  );
}
