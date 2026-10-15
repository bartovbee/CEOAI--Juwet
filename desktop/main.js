const { app, BrowserWindow, Tray, Menu, dialog, nativeImage } = require('electron');
const path = require('path');

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
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#fff"/><circle cx="16" cy="16" r="13" fill="none" stroke="#b51e2b" stroke-width="2.2"/><circle cx="16" cy="16" r="9.5" fill="none" stroke="#b51e2b" stroke-width="1.5"/><path d="M18 6v10c0 2-1 3-3 3h-3" fill="none" stroke="#111" stroke-width="3" stroke-linecap="round"/><path d="M16 20v7M9 19l4 4v4M23 19l-4 4v4" fill="none" stroke="#b51e2b" stroke-width="1.6" stroke-linecap="round"/></svg>';
  return nativeImage.createFromDataURL('data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64'));
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
app.whenReady().then(() => {
  startLocalServer();
  makeTray();
  setTimeout(createWindow, 800);
  app.on('activate', showWindow);
});
app.on('before-quit', () => { isQuitting = true; });
app.on('window-all-closed', () => {});
app.on('will-quit', () => { if (tray) tray.destroy(); });
