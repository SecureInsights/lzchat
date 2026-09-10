import type { JoinMessage, PingMessage, ServerMessage } from "../protocol/types";
import { parseJsonObject, validateServerMessage } from "../protocol/validator";

export type WsClientHandlers = {
  open: () => void;
  close: () => void;
  message: (message: ServerMessage) => void | Promise<void>;
  status: (status: string) => void;
};

const PONG_WATCHDOG_MS = 10_000;
const MAX_OUTBOX = 64;
// 蜂窝网络 NAT/运营商网关空闲超时可能短于 60s，心跳间隔收紧以保活。
const HEARTBEAT_MS_DESKTOP = 25_000;
const HEARTBEAT_MS_MOBILE = 15_000;

function isLikelyMobile(): boolean {
  const connection = (navigator as { connection?: { type?: string } }).connection;
  if (connection?.type === "cellular") {
    return true;
  }
  return /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
}

function heartbeatIntervalMs(): number {
  return isLikelyMobile() ? HEARTBEAT_MS_MOBILE : HEARTBEAT_MS_DESKTOP;
}

export class WsClient {
  #socket: WebSocket | null = null;
  #closed = false;
  #attempt = 0;
  #reconnectTimer: number | null = null;
  #heartbeatTimer: number | null = null;
  #pongTimer: number | null = null;
  #outbox: unknown[] = [];
  #onVisibility: () => void;
  #onOnline: () => void;

  constructor(
    private readonly url: string,
    private readonly joinMessage: JoinMessage,
    private readonly handlers: WsClientHandlers
  ) {
    // 移动端切后台时定时器被冻结、连接可能被系统杀掉，close 事件也可能延迟；
    // 回到前台或网络恢复时立即探活，不等心跳/退避定时器。
    this.#onVisibility = () => {
      if (document.visibilityState === "visible") {
        this.probe();
      }
    };
    this.#onOnline = () => this.probe();
    document.addEventListener("visibilitychange", this.#onVisibility);
    window.addEventListener("online", this.#onOnline);
  }

  connect(): void {
    if (this.#reconnectTimer !== null) {
      window.clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    this.#closed = false;
    this.handlers.status("连接中");
    const socket = new WebSocket(this.url);
    this.#socket = socket;
    socket.addEventListener("open", () => {
      // 陈旧连接（已被新连接替换）不得再发送 join 或触发本端会话重置。
      if (this.#isStale(socket)) {
        socket.close();
        return;
      }
      this.#attempt = 0;
      this.handlers.status("已连接");
      this.send(this.joinMessage);
      this.startHeartbeat();
      this.flushOutbox();
      this.handlers.open();
    });
    socket.addEventListener("message", (event) => {
      if (this.#isStale(socket) || typeof event.data !== "string") {
        return;
      }
      this.clearPongWatchdog();
      const parsed = validateServerMessage(parseJsonObject(event.data), this.joinMessage.roomId);
      if (!parsed) {
        return;
      }
      try {
        void Promise.resolve(this.handlers.message(parsed as ServerMessage)).catch(() => {
          this.handlers.status("消息处理失败");
        });
      } catch {
        this.handlers.status("消息处理失败");
      }
    });
    socket.addEventListener("close", () => {
      // 陈旧连接（已被新连接替换）的事件不得影响当前连接的心跳与重连调度。
      if (this.#socket !== null && this.#socket !== socket) {
        return;
      }
      if (this.#socket === socket) {
        this.#socket = null;
      }
      this.stopHeartbeat();
      this.clearPongWatchdog();
      this.handlers.close();
      if (!this.#closed) {
        this.handlers.status("已断开，正在重连");
        // ±30% 随机抖动，避免服务器恢复瞬间的重连惊群。
        const base = Math.min(500 * 2 ** Math.min(this.#attempt, 20), 5_000);
        const delay = Math.round(base * (0.7 + Math.random() * 0.6));
        this.#attempt += 1;
        this.#reconnectTimer = window.setTimeout(() => {
          this.#reconnectTimer = null;
          if (!this.#closed) {
            this.connect();
          }
        }, delay);
      }
    });
    socket.addEventListener("error", () => {
      if (this.#socket !== null && this.#socket !== socket) {
        return;
      }
      this.handlers.status("连接错误");
    });
  }

  /**
   * 移动端回到前台 / 网络恢复时的即时探活：
   * - 无连接且无重连计划 → 立即重连（不等可能被冻结过的退避定时器）；
   * - 连接仍在 OPEN → 发一次应用层 ping，由 pong 看门狗判定链路死活；
   * - 正在连接中 → 不动。
   */
  probe(): void {
    if (this.#closed) {
      return;
    }
    const socket = this.#socket;
    if (!socket || socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING) {
      if (this.#reconnectTimer === null) {
        this.connect();
      }
      return;
    }
    if (socket.readyState === WebSocket.OPEN) {
      const ping: PingMessage = {
        v: 3,
        t: "ping",
        roomId: this.joinMessage.roomId,
        clientId: this.joinMessage.clientId
      };
      if (this.send(ping)) {
        this.armPongWatchdog();
      }
    }
  }

  send(value: unknown): boolean {
    const socket = this.#socket;
    if (this.#closed) {
      return false;
    }
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return this.enqueueOutbox(value);
    }
    socket.send(JSON.stringify(value));
    return true;
  }

  isOpen(): boolean {
    return this.#socket?.readyState === WebSocket.OPEN;
  }

  bufferedAmount(): number {
    return this.#socket?.bufferedAmount ?? 0;
  }

  close(): void {
    this.#closed = true;
    document.removeEventListener("visibilitychange", this.#onVisibility);
    window.removeEventListener("online", this.#onOnline);
    this.stopHeartbeat();
    this.clearPongWatchdog();
    this.#outbox = [];
    if (this.#reconnectTimer !== null) {
      window.clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    this.#socket?.close(1000, "client closing");
    this.#socket = null;
  }

  /**
   * 强制断开底层连接但不标记“已关闭”：close 事件走正常重连流程
   * （指数退避 + 新 connectionEpoch 重 join），用于密钥链路疑似失配时快速重置。
   */
  forceReconnect(): void {
    if (this.#closed || !this.#socket) {
      return;
    }
    this.#socket.close(1000, "force reconnect");
  }

  #isStale(socket: WebSocket): boolean {
    return this.#socket !== null && this.#socket !== socket;
  }

  private enqueueOutbox(value: unknown): boolean {
    if (this.#outbox.length >= MAX_OUTBOX) {
      return false;
    }
    this.#outbox.push(value);
    return true;
  }

  private flushOutbox(): void {
    const socket = this.#socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return;
    }
    const queued = this.#outbox;
    this.#outbox = [];
    for (const value of queued) {
      socket.send(JSON.stringify(value));
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.#heartbeatTimer = window.setInterval(() => {
      const ping: PingMessage = {
        v: 3,
        t: "ping",
        roomId: this.joinMessage.roomId,
        clientId: this.joinMessage.clientId
      };
      if (this.send(ping)) {
        this.armPongWatchdog();
      }
    }, heartbeatIntervalMs());
  }

  private stopHeartbeat(): void {
    if (this.#heartbeatTimer !== null) {
      window.clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }
  }

  private armPongWatchdog(): void {
    this.clearPongWatchdog();
    this.#pongTimer = window.setTimeout(() => {
      this.#pongTimer = null;
      const socket = this.#socket;
      if (socket && socket.readyState === WebSocket.OPEN) {
        // 半开链路：ping 发出后 PONG_WATCHDOG_MS 内无任何入站帧，主动断开触发重连。
        socket.close(4000, "pong_timeout");
      }
    }, PONG_WATCHDOG_MS);
  }

  private clearPongWatchdog(): void {
    if (this.#pongTimer !== null) {
      window.clearTimeout(this.#pongTimer);
      this.#pongTimer = null;
    }
  }
}
