import * as readline from "readline";
// 扫描设备
import http from "http";
import https from "https";
import { exit } from "process";
export default class Scan {
  list: {
    ip: string;
    mac: string;
    name: string;
    sev: string;
    com: string;
    port: number[];
  }[] = [];
  list2: {
    ip: string;
    mac: string;
    name: string;
    sev: string;
    com: string;
    port: number[];
  }[] = [];
  listLen = 0;
  viewID = 0;

  onScan(arg: string) {
    console.log(`Scanning ${arg} ...\n`);
    const cmd = "nmap\\nmap.exe --script llmnr-resolve -p80,443 -d0 " + arg;
    require("child_process").exec(cmd, (err: Error, stdout: string) => {
      if (err) {
        console.error("Scanning device failed", err.message);
        return;
      }
      const stdouts: string = stdout.replace(/\r/g, "");
      const scans: string[] = stdouts.split("Nmap scan report for "); // 每個裝置
      this.list = [];
      this.list2 = [];
      for (let i = 1; i < scans.length; i++) {
        const infos: string[] = scans[i].split("\n"); // 每行資訊
        const data: {
          ip: string;
          mac: string;
          name: string;
          sev: string;
          com: string;
          port: number[];
        } = {
          ip: "",
          mac: "",
          name: "",
          sev: "",
          com: "",
          port: [],
        };
        for (let j = 0; j < infos.length; j++) {
          const line = infos[j]; // 當前行
          // console.log('line',line);
          if (j == 0) {
            // bogon (192.168.1.1)
            const nameip: string[] = infos[0].split(" ");
            data.ip = nameip.pop().replace("(", "").replace(")", "");
            data.name = nameip.join(" ").replace(/(^\s*)|(\s*$)/g, "");
          } else if (line.indexOf("/tcp") >= 0 && line.indexOf("open") >= 0) {
            // 80/tcp  open  http    syn-ack ttl 128
            data.port.push(parseInt(line.split("/")[0]));
          } else if (line.indexOf("MAC Address") >= 0) {
            const macs: string[] = line.replace("MAC Address: ", "").split(" ");
            data.mac = macs.shift();
            data.com = macs.join(" ").replace("(", "").replace(")", "");
            if (data.port.length > 0 && data.com == "Espressif") {
              this.list.push(data);
            }
          }
        }
      }
      // this.mainWindow.webContents.send("scanR", this.list);
      this.listLen = this.list.length;
      if (this.listLen == 0) {
        this.next();
      } else {
        this.getHttpPort();
      }
    });
  }

  getHttpPort(i = 0) {
    if (this.listLen == 0) {
      return;
    }
    const nowData: {
      ip: string;
      mac: string;
      name: string;
      sev: string;
      com: string;
      port: number[];
    } = this.list[i];
    let rPort = -1;
    if (nowData == undefined) {
      this.next();
      return;
    }
    if (nowData.port.indexOf(443) >= 0) {
      rPort = 443;
    } else if (nowData.port.indexOf(80) >= 0) {
      rPort = 80;
    } else {
      this.getHttpPort(i + 1);
      return;
    }
    // 调用 get 方法发送 get 请求
    const isHTTPS = rPort == 443;
    const protocol = "http" + (isHTTPS ? "s" : "") + "://";
    const getConf: {
      hostname: string;
      path: string;
      port: number;
    } = {
      hostname: nowData.ip,
      path: "/",
      port: rPort,
    };
    nowData.ip = protocol + nowData.ip;
    // const get = https.get();
    const get: http.ClientRequest = isHTTPS
      ? https.get(getConf, (res: http.IncomingMessage) => {
          this.getRes(res, nowData, i);
        })
      : http.get(getConf, (res: http.IncomingMessage) => {
          this.getRes(res, nowData, i);
        });
    get.setTimeout(5);
    get.on("error", (err) => {
      this.getHttpPort(i + 1);
    });

    get.end(); // 结束
  }

  getRes(
    res: http.IncomingMessage,
    nowData: {
      ip: string;
      mac: string;
      name: string;
      sev: string;
      com: string;
      port: number[];
    },
    i: number
  ) {
    // 如果状态码不是 200 就输出状态码
    res.on("data", (d) => {
      // console.log(nowData.ip, d.toString()); // DATA
      if (res.statusCode != 401) {
        this.getHttpPort(i + 1);
        return;
      }
      const authenticate: string = res.headers["www-authenticate"] ?? "";
      if (authenticate.length == 0) {
        this.getHttpPort(i + 1);
        return;
      }
      const authArr: string[] = authenticate.split('realm="');
      if (authArr.length != 2) {
        this.getHttpPort(i + 1);
        return;
      }
      nowData.sev = authArr[1].replace('"', "");
      this.list[i] = nowData;
      this.viewID++;
      console.log(
        `${this.viewID}  IP: ${nowData.ip}:${nowData.port},  DEVICE: ${nowData.sev},  MAC: ${nowData.mac}`
      );
      this.list2.push(nowData);
      this.getHttpPort(i + 1);
    });
  }

  next() {
    console.log("");
    const read = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    if (this.viewID == 0) {
      read.question("No device found. Press enter to exit.", (key) => {
        exit();
      });
    } else {
      read.question("Please enter ID or Ctrl+C to exit > ", (did) => {
        read.close();
        const info = this.list2[parseInt(did) - 1];
        if (info == undefined) {
          console.log("invalid id");
        } else {
          console.log(`Opening control page ${info.ip} ...`);
          const c = require("child_process");
          c.exec(`start ${info.ip}`);
        }
        this.next();
      });
    }
  }
}
