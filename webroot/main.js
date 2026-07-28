// ============================================================================
// HideAllRoot WebUI 逻辑
// 跨框架 Bridge 适配: KernelSU(ksu) / APatch(apatch) / Magisk(exec)
// 所有 Root 命令均经白名单校验，杜绝命令注入。
// ============================================================================

const MODID = 'hideallroot';
const CONFIG = `/data/adb/${MODID}/config.conf`;
const MODDIR = `/data/adb/modules/${MODID}`;

const state = {
    ENABLE_FILE_HIDE: 1, ENABLE_PROP_HIDE: 1, ENABLE_NATIVE_HOOK: 1,
    ENABLE_APPLIST_HIDE: 1, ENABLE_PROC_HIDE: 1, ENABLE_ANTIDEBUG: 1,
    ENABLE_PI_FIX: 1, ENABLE_MOUNT_HIDE: 1, TARGET_MODE: 0, DETECT_PKGS: '', CUSTOM_PKGS: '',
};

// ----- 跨框架 Shell 执行 -----
async function runShell(command) {
    let raw;
    if (typeof ksu !== 'undefined' && ksu.exec) raw = await ksu.exec(command);
    else if (typeof apatch !== 'undefined' && apatch.exec) raw = await apatch.exec(command);
    else if (typeof exec !== 'undefined') raw = await exec(command);
    else throw new Error('当前管理器不支持 WebUI Shell 执行');

    if (typeof raw === 'string') return { code: 0, out: raw, err: '' };
    if (raw && typeof raw === 'object') {
        if ('stdout' in raw) return { code: raw.errno ?? 0, out: raw.stdout ?? '', err: raw.stderr ?? '' };
        if ('out' in raw) return { code: raw.code ?? 0, out: raw.out ?? '', err: raw.err ?? '' };
    }
    return { code: 0, out: String(raw), err: '' };
}

function log(msg, isErr) {
    const area = document.getElementById('logArea');
    area.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    area.style.color = isErr ? 'var(--neon-danger)' : 'var(--neon-success)';
}

function sanitizePkgs(s) {
    // 仅允许安全字符，阻断注入
    return s.replace(/[^a-zA-Z0-9_.,-]/g, '').replace(/,{2,}/g, ',').replace(/^,|,$/g, '');
}

// ----- 解析配置 -----
function parseConfig(text) {
    const map = {};
    text.split('\n').forEach(line => {
        line = line.trim();
        if (!line || line[0] === '#') return;
        const i = line.indexOf('=');
        if (i < 0) return;
        map[line.slice(0, i)] = line.slice(i + 1).trim();
    });
    for (const k of Object.keys(state)) {
        if (map[k] !== undefined) {
            if (k === 'TARGET_MODE') state[k] = parseInt(map[k], 10) || 0;
            else state[k] = (map[k] === '1' || map[k] === 'true') ? 1 : 0;
        }
    }
    state.DETECT_PKGS = map.DETECT_PKGS || state.DETECT_PKGS;
    state.CUSTOM_PKGS = map.CUSTOM_PKGS || state.CUSTOM_PKGS;
}

// ----- 渲染 UI -----
function render() {
    document.getElementById('t_file').checked = !!state.ENABLE_FILE_HIDE;
    document.getElementById('t_prop').checked = !!state.ENABLE_PROP_HIDE;
    document.getElementById('t_native').checked = !!state.ENABLE_NATIVE_HOOK;
    document.getElementById('t_applist').checked = !!state.ENABLE_APPLIST_HIDE;
    document.getElementById('t_proc').checked = !!state.ENABLE_PROC_HIDE;
    document.getElementById('t_anti').checked = !!state.ENABLE_ANTIDEBUG;
    document.getElementById('t_pi').checked = !!state.ENABLE_PI_FIX;
    document.getElementById('t_mount').checked = !!state.ENABLE_MOUNT_HIDE;
    document.querySelectorAll('.seg-btn').forEach(b => {
        b.classList.toggle('active', parseInt(b.dataset.mode, 10) === state.TARGET_MODE);
    });
    document.getElementById('pkgInput').value =
        state.TARGET_MODE === 2 ? state.CUSTOM_PKGS : state.DETECT_PKGS;
}

function bindUI() {
    const map = { t_file: 'ENABLE_FILE_HIDE', t_prop: 'ENABLE_PROP_HIDE', t_native: 'ENABLE_NATIVE_HOOK',
        t_applist: 'ENABLE_APPLIST_HIDE', t_proc: 'ENABLE_PROC_HIDE', t_anti: 'ENABLE_ANTIDEBUG', t_pi: 'ENABLE_PI_FIX', t_mount: 'ENABLE_MOUNT_HIDE' };
    Object.keys(map).forEach(id => {
        document.getElementById(id).addEventListener('change', e => { state[map[id]] = e.target.checked ? 1 : 0; });
    });
    document.querySelectorAll('.seg-btn').forEach(b => {
        b.addEventListener('click', () => {
            state.TARGET_MODE = parseInt(b.dataset.mode, 10);
            const inp = document.getElementById('pkgInput');
            inp.value = state.TARGET_MODE === 2 ? state.CUSTOM_PKGS : state.DETECT_PKGS;
            render();
        });
    });
    document.getElementById('applyBtn').addEventListener('click', () => save(false));
    document.getElementById('rebootBtn').addEventListener('click', () => save(true));
    document.getElementById('toggleModBtn').addEventListener('click', toggleModule);
    document.getElementById('checkBtn').addEventListener('click', selfCheck);
}

// ----- 保存配置 -----
function buildConf() {
    const pkgs = sanitizePkgs(document.getElementById('pkgInput').value);
    if (state.TARGET_MODE === 2) state.CUSTOM_PKGS = pkgs; else state.DETECT_PKGS = pkgs;
    const lines = [
        '# HideAllRoot 配置（由 WebUI 生成）',
        `ENABLE_FILE_HIDE=${state.ENABLE_FILE_HIDE}`,
        `ENABLE_PROP_HIDE=${state.ENABLE_PROP_HIDE}`,
        `ENABLE_NATIVE_HOOK=${state.ENABLE_NATIVE_HOOK}`,
        `ENABLE_APPLIST_HIDE=${state.ENABLE_APPLIST_HIDE}`,
        `ENABLE_PROC_HIDE=${state.ENABLE_PROC_HIDE}`,
        `ENABLE_ANTIDEBUG=${state.ENABLE_ANTIDEBUG}`,
        `ENABLE_PI_FIX=${state.ENABLE_PI_FIX}`,
        `ENABLE_MOUNT_HIDE=${state.ENABLE_MOUNT_HIDE}`,
        `TARGET_MODE=${state.TARGET_MODE}`,
        `DETECT_PKGS=${state.DETECT_PKGS}`,
        `CUSTOM_PKGS=${state.CUSTOM_PKGS}`,
    ];
    return lines.join('\n') + '\n';
}

async function save(reboot) {
    try {
        const conf = buildConf();
        // 白名单写入，避免注入
        await runShell(`cat > ${CONFIG} <<'HAR_EOF'\n${conf}HAR_EOF`);
        await runShell(`chmod 0644 ${CONFIG}`);
        log('配置已保存（新启动的应用立即生效）');
        if (reboot) {
            log('正在重启...');
            await runShell('reboot');
        }
    } catch (e) {
        log('保存失败: ' + e.message, true);
    }
}

async function toggleModule() {
    try {
        const r = await runShell(`[ -f ${MODDIR}/disable ] && echo disabled || echo enabled`);
        if (r.out.trim() === 'disabled') {
            await runShell(`rm -f ${MODDIR}/disable`);
            log('模块已启用，请重启');
        } else {
            await runShell(`touch ${MODDIR}/disable`);
            log('模块已禁用，请重启');
        }
        refreshStatus();
    } catch (e) {
        log('操作失败: ' + e.message, true);
    }
}

// ----- 状态刷新 -----
async function refreshStatus() {
    try {
        const fw = await runShell('echo "$(getprop ro.root_manager 2>/dev/null)"; magisk -v 2>/dev/null; ksu -v 2>/dev/null; apd -v 2>/dev/null');
        document.getElementById('fwVal').textContent = fw.out.trim().split('\n').filter(Boolean)[0] || '未知';
    } catch (_) {}
    try {
        const z = await runShell('getprop persist.zygisk.enabled 2>/dev/null; getprop zygisk.enabled 2>/dev/null');
        document.getElementById('zygVal').textContent = (z.out.trim() === '1') ? '已启用' : '未知/由框架决定';
    } catch (_) {}
    try {
        const m = await runShell(`[ -f ${MODDIR}/disable ] && echo 已禁用 || echo 已启用`);
        const txt = m.out.trim() === '已禁用' ? '已禁用' : '已启用';
        document.getElementById('modVal').textContent = txt;
        const badge = document.getElementById('statusBadge');
        badge.textContent = txt;
        badge.style.borderColor = txt === '已启用' ? 'var(--neon-success)' : 'var(--neon-warn)';
        badge.style.color = txt === '已启用' ? 'var(--neon-success)' : 'var(--neon-warn)';
    } catch (_) {}
    const tmap = { 0: '全部应用', 1: '仅检测工具', 2: '仅自定义' };
    document.getElementById('tgtVal').textContent = tmap[state.TARGET_MODE] || '全部应用';
}

// ----- 自检 -----
async function selfCheck() {
    log('运行自检...');
    const checks = [
        ['su 路径', 'ls /system/bin/su /system/xbin/su /sbin/su 2>/dev/null; echo "exit:$?"'],
        ['magisk 属性', 'getprop ro.magisk.version; echo "exit:$?"'],
        ['debuggable', 'getprop ro.debuggable'],
        ['build.tags', 'getprop ro.build.tags'],
        ['magisk 目录', 'ls /data/adb/magisk 2>/dev/null; echo "exit:$?"'],
    ];
    let report = '';
    for (const [name, cmd] of checks) {
        try {
            const r = await runShell(cmd);
            report += `• ${name}: ${r.out.trim().replace(/\n/g, ' ') || '(空)'}\n`;
        } catch (e) {
            report += `• ${name}: 错误\n`;
        }
    }
    log('自检完成:\n' + report);
}

// ----- 初始化 -----
(async function init() {
    bindUI();
    try {
        const r = await runShell(`cat ${CONFIG} 2>/dev/null`);
        if (r.out) parseConfig(r.out);
    } catch (_) {}
    render();
    await refreshStatus();
    log('控制台就绪');
})();
