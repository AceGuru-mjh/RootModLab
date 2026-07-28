/* HideAllRoot v2.0 WebUI — main.js
 * 适配 KernelSU (window.kernelSU.webviewInterface) 与 Magisk/MMRL
 * (window.WebViewInterface)。配置以 base64 写回
 * /data/adb/hideallroot/config.conf。
 */
(function () {
  'use strict';

  var CONFIG_PATH = '/data/adb/hideallroot/config.conf';

  // 维度开关元数据：[key, 显示名, 说明]
  var KEYS = [
    ['ENABLE',            '总开关',            '主开关，关闭后所有隐藏停止'],
    ['ENABLE_FILE_HIDE', '文件层隐藏',        'open/openat/openat2/access/stat/readlink'],
    ['ENABLE_PROP_HIDE', '属性隐藏',          '__system_property_get / __system_property_find'],
    ['ENABLE_PROC_HIDE', '进程隐藏',          'readdir 过滤 + connect() + kill() 拦截 + PID 缓存'],
    ['ENABLE_MAPS_HIDE', 'maps 清理',         '/proc/<pid>/maps 过滤 + 匿名映射重命名防御'],
    ['ENABLE_MOUNT_HIDE','挂载点隐藏',        '/proc/mounts 与 /proc/self/mountinfo 过滤'],
    ['ENABLE_SOCKET_HIDE','守护进程 socket',  '/proc/net/unix 过滤'],
    ['ENABLE_DEBUG_HIDE','反调试',            'TracerPid 清零 + 自 ptrace 拦截'],
    ['ENABLE_UNMOUNT',   'VFS 卸载',          '卸载 Magisk tmpfs / overlay 挂载'],
    ['ENABLE_ENV_CLEAN', '环境变量清洗',      '清理 Zygisk/Magisk/KSU/APatch 变量与 PATH'],
    ['ENABLE_ZYGISK_CLEAN','Zygisk 痕迹清理', '激进清理 zygisk/frida/gum/xhook 的 maps 痕迹']
  ];

  var cfg = {};

  /* ---------- Shell 桥接 ---------- */
  function runShell(command) {
    return new Promise(function (resolve, reject) {
      try {
        var ksu = window.kernelSU && window.kernelSU.webviewInterface;
        if (ksu && typeof ksu.exec === 'function') {
          var r = ksu.exec(command);
          if (r && typeof r.then === 'function') { r.then(resolve, reject); }
          else if (ksu.exec.length >= 2) { ksu.exec(command, function (out) { resolve(out); }); }
          else { resolve(r); }
          return;
        }
        var mmrl = window.WebViewInterface;
        if (mmrl && typeof mmrl.exec === 'function') {
          var m = mmrl.exec(command);
          if (m && typeof m.then === 'function') { m.then(resolve, reject); }
          else { resolve(m); }
          return;
        }
        reject(new Error('当前管理器不支持 WebUI Shell，请使用 KernelSU 或 Magisk(MMRL)。'));
      } catch (e) { reject(e); }
    });
  }

  /* ---------- 工具 ---------- */
  function $(id) { return document.getElementById(id); }

  function toast(msg) {
    var t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.classList.remove('show'); }, 1900);
  }

  function parseCfg(text) {
    cfg = {};
    (text || '').split('\n').forEach(function (line) {
      line = line.trim();
      if (!line || line.indexOf('#') === 0) return;
      var i = line.indexOf('=');
      if (i < 0) return;
      var k = line.slice(0, i).trim();
      var v = line.slice(i + 1).trim();
      cfg[k] = v;
    });
  }

  function b64encode(str) {
    return btoa(unescape(encodeURIComponent(str)));
  }

  function buildConfigText() {
    var lines = [];
    lines.push('# HideAllRoot v2.0 配置（由 WebUI 生成）');
    KEYS.forEach(function (kv) {
      lines.push(kv[0] + '=' + (cfg[kv[0]] === '1' ? '1' : '0'));
    });
    lines.push('TARGET_MODE=' + (cfg['TARGET_MODE'] || '0'));
    lines.push('TARGET_PKGS=' + (cfg['TARGET_PKGS'] || ''));
    lines.push('CUSTOM_PKGS=' + (cfg['CUSTOM_PKGS'] || ''));
    return lines.join('\n') + '\n';
  }

  /* ---------- 渲染 ---------- */
  function renderConfig() {
    var box = $('configRows');
    box.innerHTML = '';
    KEYS.forEach(function (kv) {
      var k = kv[0], name = kv[1], desc = kv[2];
      var row = document.createElement('div');
      row.className = 'row';
      var left = document.createElement('div');
      left.innerHTML = '<div class="label">' + name + '</div><div class="desc">' + desc + '</div>';
      var sw = document.createElement('label');
      sw.className = 'sw';
      var on = cfg[k] === '1';
      sw.innerHTML = '<input type="checkbox" ' + (on ? 'checked' : '') + '>' +
                     '<span class="slider"></span>';
      sw.querySelector('input').addEventListener('change', function (e) {
        cfg[k] = e.target.checked ? '1' : '0';
      });
      row.appendChild(left);
      row.appendChild(sw);
      box.appendChild(row);
    });
  }

  function renderTarget() {
    var mode = cfg['TARGET_MODE'] || '0';
    var seg = $('targetSeg');
    Array.prototype.forEach.call(seg.children, function (b) {
      b.className = (b.getAttribute('data-v') === mode) ? 'on' : '';
    });
    var hint = {
      '0': '对所有应用生效（覆盖面最广，推荐）。',
      '1': '仅对“检测工具包名”中的应用隐藏，性能最佳。',
      '2': '仅对“自定义包名”中的应用隐藏。'
    }[mode] || '';
    $('targetHint').textContent = hint;
  }

  function renderPkgs() {
    $('targetPkgs').value = cfg['TARGET_PKGS'] || '';
    $('customPkgs').value = cfg['CUSTOM_PKGS'] || '';
  }

  function renderDashboard() {
    var en = cfg['ENABLE'] === '1';
    var badge = $('statusBadge');
    badge.textContent = en ? '已启用' : '已停用';
    badge.className = 'badge ' + (en ? 'ok' : '');
    $('stModule').textContent = en ? '✔' : '✘';
    var n = 0;
    KEYS.forEach(function (kv) { if (kv[0] !== 'ENABLE' && cfg[kv[0]] === '1') n++; });
    $('stTraces').textContent = n;
    var mode = cfg['TARGET_MODE'] || '0';
    $('stTarget').textContent = mode === '0' ? '全部' : (mode === '1' ? '检测工具' : '自定义');

    var tags = $('dashTags');
    tags.innerHTML = '';
    KEYS.forEach(function (kv) {
      if (kv[0] !== 'ENABLE' && cfg[kv[0]] === '1') {
        var s = document.createElement('span');
        s.className = 'pill on';
        s.textContent = kv[1];
        tags.appendChild(s);
      }
    });
    if (!tags.children.length) {
      var e = document.createElement('span');
      e.className = 'pill';
      e.textContent = '无（总开关可能已关闭）';
      tags.appendChild(e);
    }
  }

  function renderAll() {
    renderConfig();
    renderTarget();
    renderPkgs();
    renderDashboard();
  }

  /* ---------- 动作 ---------- */
  function saveConfig() {
    // 仅当包名页被编辑过才同步
    cfg['TARGET_PKGS'] = ($('targetPkgs').value || '').trim();
    cfg['TARGET_PKGS'] = cfg['TARGET_PKGS'].replace(/\s+/g, '');
    cfg['CUSTOM_PKGS'] = ($('customPkgs').value || '').trim().replace(/\s+/g, '');
    var text = buildConfigText();
    var b64 = b64encode(text);
    runShell("printf '%s' '" + b64 + "' | base64 -d > " + CONFIG_PATH)
      .then(function () { toast('✅ 配置已保存'); })
      .catch(function (e) { toast('⚠️ 保存失败: ' + e.message); });
  }

  function loadConfig() {
    runShell('cat ' + CONFIG_PATH)
      .then(function (out) {
        parseCfg(out || '');
        if (!cfg['ENABLE'] && !(out || '').trim()) {
          toast('未找到配置，可能尚未安装');
        }
        renderAll();
      })
      .catch(function (e) {
        $('statusBadge').textContent = '离线';
        toast('⚠️ 读取配置失败: ' + e.message);
      });
  }

  function selfTest() {
    var log = $('selftestLog');
    log.style.display = 'block';
    log.textContent = '运行中…';
    var cmd = 'echo "== props =="; ' +
      'getprop ro.build.tags; getprop ro.debuggable; getprop ro.secure; ' +
      'echo "== mounts(magisk) =="; cat /proc/mounts 2>/dev/null | grep -i magisk | head -n 3; ' +
      'echo "== daemons =="; ps -A 2>/dev/null | grep -iE "magisk|zygisk|ksu|apatch" | head -n 5; ' +
      'echo "== done =="';
    runShell(cmd)
      .then(function (out) {
        log.textContent = (out && out.trim()) ? out : '未检测到明显 Root 痕迹 ✅';
        toast('自检完成');
      })
      .catch(function (e) { log.textContent = '自检失败: ' + e.message; });
  }

  function showLogcat() {
    var v = $('logcatView');
    v.style.display = 'block';
    v.textContent = '抓取中…';
    runShell('logcat -d -t 300 -s HideAllRoot:V')
      .then(function (out) {
        v.textContent = (out && out.trim()) ? out : '（无 HideAllRoot 日志）';
      })
      .catch(function (e) { v.textContent = '失败: ' + e.message; });
  }

  function showCfg() {
    runShell('cat ' + CONFIG_PATH)
      .then(function (out) { $('cfgView').textContent = out || '（空）'; })
      .catch(function (e) { $('cfgView').textContent = '读取失败: ' + e.message; });
  }

  /* ---------- 事件绑定 ---------- */
  function bind() {
    // tabs
    var tabs = document.getElementById('tabs');
    Array.prototype.forEach.call(tabs.querySelectorAll('.tab'), function (t) {
      t.addEventListener('click', function () {
        var page = t.getAttribute('data-page');
        Array.prototype.forEach.call(tabs.querySelectorAll('.tab'), function (x) {
          x.classList.toggle('active', x === t);
        });
        Array.prototype.forEach.call(document.querySelectorAll('.page'), function (p) {
          p.classList.toggle('active', p.id === 'page-' + page);
        });
        if (page === 'log') showCfg();
      });
    });

    // target seg
    var seg = $('targetSeg');
    Array.prototype.forEach.call(seg.querySelectorAll('button'), function (b) {
      b.addEventListener('click', function () {
        cfg['TARGET_MODE'] = b.getAttribute('data-v');
        renderTarget();
      });
    });

    $('btnSaveConfig').addEventListener('click', saveConfig);
    $('btnSavePkgs').addEventListener('click', saveConfig);
    $('btnSelftest').addEventListener('click', selfTest);
    $('btnLogcat').addEventListener('click', showLogcat);
    $('btnReloadCfg').addEventListener('click', showCfg);
  }

  document.addEventListener('DOMContentLoaded', function () {
    bind();
    loadConfig();
  });
})();
