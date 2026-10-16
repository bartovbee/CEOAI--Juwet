const { app, BrowserWindow, Tray, Menu, dialog, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow = null;
let tray = null;
let serverStarted = false;
let isQuitting = false;
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8787);
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);

function getPortableRoot() {
  return process.env.PORTABLE_EXECUTABLE_DIR || path.dirname(process.execPath);
}
function startLocalServer() {
  if (serverStarted) return;
  serverStarted = true;
  process.env.CEOAI_DATA_DIR = process.env.CEOAI_DATA_DIR || path.join(getPortableRoot(), 'data');
  process.env.CEOAI_OPEN_BROWSER = '0';
  require(path.join(__dirname, '..', 'server.js'));
}
function makeTrayIcon() {
  const candidates = [
    path.join(__dirname, '..', 'build', 'ceoai-juwet.png'),
    path.join(__dirname, '..', 'public', 'logo.svg')
  ];
  for (const candidate of candidates) {
    try {
      const icon = nativeImage.createFromPath(candidate);
      if (!icon.isEmpty()) return icon.resize({ width: 32, height: 32 });
    } catch {}
  }
  return nativeImage.createEmpty();
}
function showWindow() {
  if (!mainWindow) createWindow();
  else {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  }
}
function makeTray() {
  if (tray) return;
  tray = new Tray(makeTrayIcon());
  tray.setToolTip('CEOAI Juwet · Proxy ' + PROXY_PORT);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Buka CEOAI Juwet', click: showWindow },
    { label: 'Status Proxy', enabled: false },
    { label: 'Proxy port: ' + PROXY_PORT, enabled: false },
    { label: 'Dashboard internal: ' + DASHBOARD_PORT, enabled: false },
    { type: 'separator' },
    { label: 'Keluar', click: () => { isQuitting = true; app.quit(); } }
  ]));
  tray.on('double-click', showWindow);
  tray.on('click', showWindow);
}
function createWindow() {
  if (mainWindow) return showWindow();
  mainWindow = new BrowserWindow({
    width: 1180, height: 780, minWidth: 900, minHeight: 600,
    show: false, autoHideMenuBar: true, backgroundColor: '#f4f7fb',
    title: 'CEOAI Juwet',
    icon: path.join(__dirname, '..', 'build', 'ceoai-juwet.ico'),
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  mainWindow.once('ready-to-show', () => mainWindow && mainWindow.show());
  mainWindow.on('close', event => {
    if (!isQuitting) { event.preventDefault(); mainWindow.hide(); }
  });
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.loadURL('http://127.0.0.1:' + DASHBOARD_PORT).catch(async error => {
    await dialog.showMessageBox({ type: 'error', title: 'CEOAI Juwet',
      message: 'Aplikasi gagal membuka jendela utama.', detail: error.message });
  });
}
process.on('ceoai-server-error', async detail => {
  try {
    await dialog.showMessageBox({
      type: 'error',
      title: 'CEOAI Juwet - Port tidak tersedia',
      message: 'CEOAI Juwet tidak dapat memulai layanan ' + detail.server + '.',
      detail: 'Port: ' + detail.port + '\\nKode: ' + detail.code + '\\n' + detail.error + '\\n\\nTutup aplikasi lain yang memakai port tersebut, lalu jalankan CEOAI Juwet kembali.'
    });
  } finally {
    isQuitting = true;
    app.quit();
  }
});
app.whenReady().then(() => {
  startLocalServer();
  makeTray();
  setTimeout(createWindow, 800);
  app.on('activate', showWindow);
});
app.on('before-quit', () => { isQuitting = true; });
app.on('window-all-closed', () => {});
app.on('will-quit', () => { if (tray) tray.destroy(); });
