//! Claude Science（原生 Windows）相关命令。

use tauri::State;

use crate::claude_science::{self, LaunchReport, ScienceStatus};
use crate::AppState;

#[tauri::command]
pub fn claude_science_status() -> ScienceStatus {
    claude_science::status()
}

/// 启动隔离的 Claude Science，并把推理指向本地代理的 /claude-science 路由。
///
/// 代理未运行时先拉起它；Science 只接受字面 loopback 的 http 地址。
#[tauri::command]
pub async fn claude_science_launch(state: State<'_ , AppState>) -> Result<LaunchReport, String> {
    if !state.proxy_service.is_running().await {
        state.proxy_service.start().await?;
    }
    let (host, port) = state.db.get_proxy_client_endpoint_sync();
    if port == 0 {
        return Err("本地代理尚未监听；请先在界面上启动本地代理或固定端口".to_string());
    }
    let proxy_base = crate::services::proxy::proxy_origin(&host, port);
    claude_science::launch(&proxy_base)
}

#[tauri::command]
pub fn claude_science_stop() -> Result<String, String> {
    claude_science::stop()
}
