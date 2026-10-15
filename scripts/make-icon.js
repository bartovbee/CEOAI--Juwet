const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const pngToIco = require('png-to-ico');

(async () => {
  const root = path.join(__dirname, '..');
  const svgPath = path.join(root, 'public', 'logo.svg');
  const outDir = path.join(root, 'build');
  const icoPath = path.join(outDir, 'ceoai-juwet.ico');
  const pngPath = path.join(outDir, 'ceoai-juwet.png');
  fs.mkdirSync(outDir, { recursive: true });
  const png = await sharp(svgPath, { density: 384 })
    .resize(256, 256, { fit: 'contain' })
    .png()
    .toBuffer();
  fs.writeFileSync(pngPath, png);
  const ico = await pngToIco(png);
  fs.writeFileSync(icoPath, ico);
  console.log('Created branded Windows icon:', icoPath, ico.length, 'bytes; tray PNG:', pngPath);
})().catch(error => {
  console.error(error);
  process.exit(1);
});
