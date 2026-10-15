const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');

let mainWindow;
let serverStarted = false;
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8787);

function startLocalServer() {
  if (serverStarted) return;
  serverStarted = true;
  // Server runs inside the desktop app process; no separate console window.
  require(path.join(__dirname, 'server.js'));
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 850,
    minWidth: 920,
    minHeight: 620,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: '#f4f7fb',
    title: 'CEOAI Juwet',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.loadURL('http://127.0.0.1:' + DASHBOARD_PORT).catch(async error => {
    await dialog.showMessageBox({
      type: 'error',
      title: 'CEOAI Juwet',
      message: 'Dashboard lokal gagal dibuka.',
      detail: error.message
    });
  });
}

app.whenReady().then(() => {
  startLocalServer();
  setTimeout(createWindow, 700);
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
