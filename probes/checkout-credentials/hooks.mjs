import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import {syncBuiltinESMExports} from 'node:module';

const task = JSON.parse(fs.readFileSync('/case/task.json', 'utf8'));
const append = fs.appendFileSync.bind(fs);
const originalWrite = fs.promises.writeFile.bind(fs.promises);
const originalRm = fs.promises.rm.bind(fs.promises);
function event(name) {
  const file = '/case/events';
  const data = name + '\n';
  const size = fs.existsSync(file) ? fs.statSync(file).size : 0;
  if (size + Buffer.byteLength(data) > 65536) throw new Error('event-limit');
  append(file, data, {mode: 0o600});
}
function credential(file) {
  return typeof file === 'string' && path.dirname(file) === '/case/temp' &&
    /^git-credentials-[0-9a-f-]+\.config$/i.test(path.basename(file));
}
fs.promises.writeFile = async function(file, ...rest) {
  const result = await originalWrite(file, ...rest);
  if (credential(file)) {
    event('token-written');
    if (task.kind === 'extra-file') {
      await originalWrite('/case/temp/git-credentials-00000000-0000-4000-8000-000000000099.config', '', {mode: 0o600});
      event('extra-file');
    }
    if (task.kind === 'cancel') {
      event('cancel-ready');
      await new Promise(() => {setInterval(() => {}, 1000);});
    }
  }
  return result;
};
fs.promises.rm = async function(file, ...rest) {
  if (credential(file) && task.kind === 'delete') {
    event('delete-denied');
    const error = new Error('owned-removal-denied'); error.code = 'EACCES'; throw error;
  }
  return originalRm(file, ...rest);
};
function deny() {event('network-denied'); throw new Error('owned-network-denied');}
net.connect = deny; net.createConnection = deny;
tls.connect = deny;
http.request = deny; http.get = deny;
https.request = deny; https.get = deny;
dgram.createSocket = deny;
globalThis.fetch = deny;
syncBuiltinESMExports();
