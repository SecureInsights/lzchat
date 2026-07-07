import type { JoinMessage, ServerMessage } from "../protocol/types";
import { parseJsonObject } from "../protocol/validator";

export type WsClientHandlers = {
  open: () => void;
  close: () => void;
  message: (message: ServerMessage) => void;
  status: (status: string) => void;
};

export class WsClient {
  #socket: WebSocket | null = null;
  #closed = false;
  #attempt = 0;

  constructor(
    private readonly url: string,
    private readonly joinMessage: JoinMessage,
    private readonly handlers: WsClientHandlers
  ) {}

  connect(): void {
    this.#closed = false;
    this.handlers.status("连接中");
    const socket = new WebSocket(this.url);
    this.#socket = socket;
    socket.addEventListener("open", () => {
      this.#attempt = 0;
      this.handlers.status("已连接");
      this.send(this.joinMessage);
      this.handlers.open();
    });
    socket.addEventListener("message", (event) => {
      if (typeof event.data !== "string") {
        return;
      }
      const parsed = parseJsonObject(event.data);
      if (!parsed || parsed.v !== 3) {
        return;
      }
      this.handlers.message(parsed as ServerMessage);
    });
    socket.addEventListener("close", () => {
      if (this.#socket === socket) {
        this.#socket = null;
      }
      this.handlers.close();
      if (!this.#closed) {
        this.handlers.status("已断开，正在重连");
        const delay = Math.min(500 * 2 ** this.#attempt, 5_000);
        this.#attempt += 1;
        window.setTimeout(() => this.connect(), delay);
      }
    });
    socket.addEventListener("error", () => {
      this.handlers.status("连接错误");
    });
  }

  send(value: unknown): void {
    const socket = this.#socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return;
    }
    socket.send(JSON.stringify(value));
  }

  close(): void {
    this.#closed = true;
    this.#socket?.close(1000, "client closing");
    this.#socket = null;
  }
}
