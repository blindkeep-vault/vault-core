import { readFileSync, writeFileSync } from "node:fs";
const [spkiPath, keyPath, outPath] = process.argv.slice(2);
const pub = await crypto.subtle.importKey("spki", readFileSync(spkiPath), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, readFileSync(keyPath));
writeFileSync(outPath, Buffer.from(ct));
